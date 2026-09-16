import "pe"
rule _NoobyProtect_SE_Public_V1160__Nooby__20090201_
{
	meta:
		description = "NoobyProtect SE Public V1.1.6.0 -> Nooby * 20090201"
	strings:
		$0 = {E9 ?? 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E 31 2E 36 2E 30}
	condition:
		$0 at pe.entry_point
}