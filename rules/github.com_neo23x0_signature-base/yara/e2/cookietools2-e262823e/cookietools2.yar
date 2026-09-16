rule CookieTools2 {
	meta:
		description = "Chinese Hacktool Set - file CookieTools2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cb67797f229fdb92360319e01277e1345305eb82"
		id = "f227ba4b-9cad-5aac-99ab-46a8237249d4"
	strings:
		$s1 = "www.gxgl.com&www.gxgl.net" fullword wide
		$s2 = "ip.asp?IP=" fullword ascii
		$s3 = "MSIE 5.5;" fullword ascii
		$s4 = "SOFTWARE\\Borland\\" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}