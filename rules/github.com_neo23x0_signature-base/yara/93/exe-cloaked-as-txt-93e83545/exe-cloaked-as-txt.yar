rule EXE_cloaked_as_TXT {
	meta:
		description = "Executable with TXT extension"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		id = "2188c0fe-71b0-5dee-bde9-f310c66e39c6"
	condition:
		uint16(0) == 0x5a4d 							and filename matches /\.txt$/is   }