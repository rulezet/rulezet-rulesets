rule perplex101dev
{
	meta:
		author = "PEiD"
		description = "Perplex PE-Protector 1.01dev -> tC/PERPLEX"
		group = "195"
		function = "0"
	strings:
		$a0 = { 60 E9 8D 05 00 00 }
	condition:
		$a0
}