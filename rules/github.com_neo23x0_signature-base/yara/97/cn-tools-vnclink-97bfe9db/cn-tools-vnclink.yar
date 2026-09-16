rule CN_Tools_VNCLink {
	meta:
		description = "Chinese Hacktool Set - file VNCLink.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cafb531822cbc0cfebbea864489eebba48081aa1"
		id = "270dc14c-ac8f-58c2-b4ac-c10981e20a07"
	strings:
		$s1 = "C:\\temp\\vncviewer4.log" fullword ascii
		$s2 = "[BL4CK] Patched by redsand || http://blacksecurity.org" fullword ascii
		$s3 = "fake release extendedVkey 0x%x, keysym 0x%x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 580KB and 2 of them
}