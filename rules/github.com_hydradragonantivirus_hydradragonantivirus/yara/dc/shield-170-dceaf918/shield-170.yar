import "pe"
rule _Shield_170_
{
	meta:
		description = "Shield 1.70"
	strings:
		$0 = {2E 8C 06 D5 05 2E 87 06 D3 05 8B EC B9 C3 03 90 33 DB 02 46 00 12 E7 45 E2 F8 8C CE 8E DB FA BC 22 02 59 5A 87 0F 43 43 03 D6 87 17 52 51 43 43 83 EC 04 80 FB 10 72 EA CC 90 25 73 67 2B 98 02 FB 5D 07 5A 5F 8B 3D 8B 4E 05 33 C7 33 C1 D1 C0}
	condition:
		$0 at pe.entry_point
}