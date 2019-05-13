# Trap-a-Track

Honeypots are often used to recognize breaches behind the defense line, recognizing unusual traffic.
[CanaryTokens](https://blog.thinkst.com/p/canarytokensorg-quick-free-detection.html) are files that can be distributed in strategic locations to discover insider attacks, breaches and data theft.

Neither solutions are able to identify the user and get more context for an insider attack.
Trap-a-Track is supposed to close this gap by automatically getting detailed information about who is running the token, allowing to quickly identify insiders within a global enterprise.

## How does it work?

Trap-a-Track generates executables that can be spread on network drives and other locations.
They can optically imitate other files (like password files) to make it more appealing for attackers to open them.

After a user clicked on it, Trap-a-Track will

1. Restart `explorer.exe` to reduce suspicion
2. Grant permission for the webcam and microphone
3. Capture the webcam and microphone for a configurable duration by using a statically linked ffmpeg version (default 10 seconds)
4. Create a screenshot of the current desktop
5. Generate a [unique hardware ID](https://github.com/denisbrodbeck/machineid) and collect system information like network interfaces, saved wifi profiles, device configuration and running tasks.
6. Zip and encrypt this information using a public GPG key
7. Upload the encrypted file to a server
8. Delete all files locally

# Server

Simply copy the `server` folder to a public website running PHP.
Make sure to add this URL to to the client.

# Client

The client is the part that is executed by a potential attacker.
All commands below expect you to change into the `client` folder.

## Configuration

The following configuration is available at the top of `trapatrack.go`.

```golang
var (
	REPORT_URL = "https://example.com/report.php"
	CAPTURE_TIME = "00:00:10"
	
	PRIVACY_CAPTURE_GENERAL = true
	PRIVACY_CAPTURE_VIDEO = true
	PRIVACY_CAPTURE_AUDIO = false
)
```

You will need to replace the public key at `assets/public.pem`.

## Building from source

Trap-a-Track bundles all data within its executable.
While this allows a maximum of mobility, it means that it needs to be build from source.

If you would like to change the metadata of the file, you can edit `versioninfo.json` or replace `assets/icon.ico` with the icon of your choice.
You need to run `go generate` to have those changes applied.

To create the binary, import all dependancies via `go get ./...` and build it using `packr2 build -ldflags -H=windowsgui`.
All assets are automatically packed via [packr](https://github.com/gobuffalo/packr).

# Sponsors

[![Panasonic Information Systems Company Europe](https://raw.githubusercontent.com/JamesCullum/Trap-A-Track/master/.github/PISCEU_logo.png)](https://application.job.panasonic.eu/data/ruP0pHQvHrGZJKvL/rc.php?nav=jobsearch&custval12=ite&lang=EN&custval11=PBSEU_GER)