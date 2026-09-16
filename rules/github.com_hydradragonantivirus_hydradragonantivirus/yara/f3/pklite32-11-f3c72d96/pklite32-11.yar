import "pe"
rule _PKLITE32_11_
{
	meta:
		description = "PKLITE32 1.1"
	strings:
		$0 = {50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31}
	condition:
		$0 at pe.entry_point
}