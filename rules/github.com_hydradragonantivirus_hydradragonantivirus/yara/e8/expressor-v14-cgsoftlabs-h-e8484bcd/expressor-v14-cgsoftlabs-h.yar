import "pe"
rule _eXPressor_v14__CGSoftLabs_h_
{
	meta:
		description = "eXPressor v1.4 -> CGSoftLabs (h)"
	strings:
		$0 = {55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8}
	condition:
		$0 at pe.entry_point
}