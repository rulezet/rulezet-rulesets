import "pe"
rule _Morphine_v12__v13_
{
	meta:
		description = "Morphine v1.2 - v1.3"
	strings:
		$0 = {FF 25 34 ?? 5A 00 8B C0 FF 25 38 ?? 5A 00 8B C0}
	condition:
		$0 at pe.entry_point
}