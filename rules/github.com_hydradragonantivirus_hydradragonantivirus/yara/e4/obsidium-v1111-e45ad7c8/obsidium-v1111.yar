import "pe"
rule _Obsidium_v1111_
{
	meta:
		description = "Obsidium v1.1.1.1"
	strings:
		$0 = {E8 AB}
	condition:
		$0 at pe.entry_point
}