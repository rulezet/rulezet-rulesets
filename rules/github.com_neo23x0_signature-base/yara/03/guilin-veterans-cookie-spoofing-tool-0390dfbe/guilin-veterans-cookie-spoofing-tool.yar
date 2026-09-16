rule Guilin_veterans_cookie_spoofing_tool {
	meta:
		description = "Chinese Hacktool Set - file Guilin veterans cookie spoofing tool.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2023-01-27"
		hash = "06b1969bc35b2ee8d66f7ce8a2120d3016a00bb1"
		id = "13f78e0b-c975-5879-9af1-8c619d6c94a9"
	strings:
		$s0 = "kernel32.dll^G" fullword ascii
		$s1 = "\\.Sus\"B" ascii
		$s4 = "u56Load3" fullword ascii
		$s11 = "O MYTMP(iM) VALUES (" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1387KB and all of them
}