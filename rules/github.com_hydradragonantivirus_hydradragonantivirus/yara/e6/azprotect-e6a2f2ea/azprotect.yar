import "pe"
rule _AZProtect_
{
	meta:
		description = "AZProtect"
	strings:
		$0 = {EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30}
	condition:
		$0 at pe.entry_point
}