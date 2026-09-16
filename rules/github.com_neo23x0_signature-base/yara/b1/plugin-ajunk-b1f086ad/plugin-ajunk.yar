rule PLUGIN_AJunk {
	meta:
		description = "Chinese Hacktool Set - file AJunk.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "eb430fcfe6d13b14ff6baa4b3f59817c0facec00"
		id = "af92d01d-5e24-52f7-934a-0ad102fc7a93"
	strings:
		$s1 = "AJunk.dll" fullword ascii
		$s2 = "AJunk.DLL" fullword wide
		$s3 = "AJunk Dynamic Link Library" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 560KB and all of them
}