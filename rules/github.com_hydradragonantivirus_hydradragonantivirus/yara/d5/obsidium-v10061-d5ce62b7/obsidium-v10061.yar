import "pe"
rule _Obsidium_v10061_
{
	meta:
		description = "Obsidium v1.0.0.61"
	strings:
		$0 = {E8 47}
	condition:
		$0 at pe.entry_point
}