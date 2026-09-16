rule Dubnium_Sample_2 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
		id = "894dc893-25fc-5fdc-9f69-8085b94e1af1"
	strings:
		$x1 = ":*:::D:\\:c:~:" fullword ascii
		$s2 = "SPMUVR" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}