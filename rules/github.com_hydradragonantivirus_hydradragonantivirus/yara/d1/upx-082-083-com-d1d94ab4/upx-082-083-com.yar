import "pe"
rule _UPX_082__083_COM_
{
	meta:
		description = "UPX 0.82 - 0.83 [COM]"
	strings:
		$0 = {81 FC 00 00 77 02 CD 20 B9 00 00 BE 00 00 BF 00 00 BB 00 80 FD F3 A4 FC 87 F7 83 EE C6 19 ED 57 57 E9 00 00 55 50 58 21 0A 01 04 07 00 00 00 00 00 00 00 00 00 00 00 00 06 00 FF FF}
	condition:
		$0 at pe.entry_point
}