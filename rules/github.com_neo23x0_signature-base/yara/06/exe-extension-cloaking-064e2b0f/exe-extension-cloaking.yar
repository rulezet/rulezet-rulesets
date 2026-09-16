rule EXE_extension_cloaking {
	meta:
		description = "Executable showing different extension (Windows default 'hide known extension')"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		id = "78da6129-a11d-5e9e-8eaf-2a18178b7278"
	condition:
		filename matches /\.txt\.exe$/is or			filename matches /\.pdf\.exe$/is		}