rule APT30_Generic_H {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "2a4c8752f3e7fde0139421b8d5713b29c720685d"
		hash2 = "4350e906d590dca5fcc90ed3215467524e0a4e3d"
		id = "1908e985-9634-51dc-8972-53afa13c26a3"
	strings:
		$s0 = "\\Temp1020.txt" ascii
		$s1 = "Xmd.Txe" fullword ascii
		$s2 = "\\Internet Exp1orer" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}