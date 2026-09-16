rule APT30_Generic_E_v2 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "eca53a9f6251ddf438508b28d8a483f91b99a3fd"
		id = "40897687-fb17-568e-9907-e9588a53bbe0"
	strings:
		$s0 = "Nkfvtyvn}duf_Z}{Ys" fullword ascii
		$s1 = "Nkfvtyvn}*Zrswru1i" fullword ascii
		$s2 = "Nkfvtyvn}duf_Z}{V" fullword ascii
		$s3 = "Nkfvtyvn}*ZrswrumT\\b" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}