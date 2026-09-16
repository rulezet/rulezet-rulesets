import "pe"
rule _FSG_v11_
{
	meta:
		description = "FSG v1.1"
	strings:
		$0 = {4B 45 52 4E 45 4C 33 32 2E 64 6C 6C ?? ?? 4C 6F 61 64 4C 69 62 72 61 72 79 41 ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73}
	condition:
		$0 at pe.entry_point
}