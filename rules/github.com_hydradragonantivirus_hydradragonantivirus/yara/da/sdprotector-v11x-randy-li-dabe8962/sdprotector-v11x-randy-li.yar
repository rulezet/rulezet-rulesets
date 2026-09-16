import "pe"
rule _SDProtector_V11x__Randy_Li_
{
	meta:
		description = "SDProtector V1.1x -> Randy Li"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1}
	condition:
		$0 at pe.entry_point
}