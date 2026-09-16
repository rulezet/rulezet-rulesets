import "pe"
rule _Watcom_C_1995_
{
	meta:
		description = "Watcom C (1995)"
	strings:
		$0 = {FB B9 00 00 8E C1 26 BB 00 00 83 C3 0F 80 E3 F0 26 89 1E 00 00 26 8C 1E 00 00 01 E3 83 C3 0F 80 E3 F0 8E D1 89 DC 26 89 1E 00 00 89 DA D1 EA D1 EA D1 EA D1 EA 26 80 3E 00 00 00 75 3D 8B 0E 02 00 8C C0 29 C1 39 CA 72 0B BB 01 00 B8 00 00 8C}
	condition:
		$0 at pe.entry_point
}