rule Cloaked_RAR_File {
	meta:
		description = "RAR file cloaked by a different extension"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		id = "a3a9ad40-8a39-513d-be95-73f5a909265e"
	condition:
		uint32be(0) == 0x52617221									and not filename matches /(rarnew.dat|\.rar)$/is			and not filename matches /\.[rR][\d]{2}$/           		and not filepath contains "Recycle" 				}