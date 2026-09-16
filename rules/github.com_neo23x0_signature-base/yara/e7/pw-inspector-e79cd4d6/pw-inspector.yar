rule pw_inspector {
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4f8e3e101098fc3da65ed06117b3cb73c0a66215"
		id = "888db647-c5d0-5b1b-bcd2-512c1ebeadea"
	strings:
		$s1 = "-m MINLEN  minimum length of a valid password" fullword ascii
		$s2 = "http://www.thc.org" fullword ascii
		$s3 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 460KB and all of them
}