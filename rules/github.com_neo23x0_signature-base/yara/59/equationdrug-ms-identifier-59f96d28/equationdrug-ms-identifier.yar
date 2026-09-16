import "pe"
rule EquationDrug_MS_Identifier {
	meta:
		description = "Microsoft Identifier used in EquationDrug Platform"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		date = "2015/03/11"
		id = "c934c117-bf5a-5688-acd9-5d6c6aacd6bc"
	strings:
		$s1 = "Microsoft(R) Windows (TM) Operating System" fullword wide
	condition:
				$s1 and pe.timestamp > 946684800
}