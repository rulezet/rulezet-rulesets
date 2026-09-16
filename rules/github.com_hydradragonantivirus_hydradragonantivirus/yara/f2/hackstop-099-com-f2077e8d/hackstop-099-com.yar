import "pe"
rule _HackStop_099_COM_
{
	meta:
		description = "HackStop 0.99 [COM]"
	strings:
		$0 = {50 B4 30 CD 21 86 E0 3D 00 03 73 02 CD 20 EB 02 53 8F 50 55 52 8C D2 FA 50 B8 EB 04 58 EB FB 9A 8C C8 8E D0 EB 02 69 8F 8B EC BC 03 00 2E 85 06 D8 F6 B8 EB 03 EB FC EA 83 FC 03 74 02 FA F4 2E 85 06 EA F6 B8 EB 03 EB FC EA 33 C0 FA 8E D0 BC}
	condition:
		$0 at pe.entry_point
}