rule APT30_Sample_16 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "066d06ac08b48d3382d46bbeda6ad411b6d6130e"
		id = "e5dd6bc9-9383-5d48-92df-709996373655"
	strings:
		$s0 = "\\Temp1020.txt" ascii
		$s1 = "cmcbqyjs" fullword ascii
		$s2 = "SPVSWh\\" fullword ascii
		$s4 = "PSShxw@" fullword ascii
		$s5 = "VWhHw@" fullword ascii
		$s7 = "SVWhHw@" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}