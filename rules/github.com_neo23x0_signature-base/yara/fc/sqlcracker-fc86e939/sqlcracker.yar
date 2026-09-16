rule SQLCracker {
	meta:
		description = "Chinese Hacktool Set - file SQLCracker.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"
		id = "7d7ff2cf-81fb-5a04-a97f-577c306137a9"
	strings:
		$s0 = "msvbvm60.dll" fullword ascii 
		$s1 = "_CIcos" fullword ascii
		$s2 = "kernel32.dll" fullword ascii
		$s3 = "cKmhV" fullword ascii
		$s4 = "080404B0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 125KB and all of them
}