rule HTTPSCANNER {
	meta:
		description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"
		id = "470c90f5-bb98-59ab-bff4-f6238c318e36"
	strings:
		$s1 = "HttpScanner.exe" fullword wide
		$s2 = "HttpScanner" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 3500KB and all of them
}