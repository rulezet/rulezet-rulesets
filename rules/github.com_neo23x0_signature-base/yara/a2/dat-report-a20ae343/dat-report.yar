rule dat_report {
	meta:
		description = "Chinese Hacktool Set - file report.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"
		id = "c77633a7-0c2f-5efa-b58b-635546bfec95"
	strings:
		$s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
		$s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 480KB and all of them
}