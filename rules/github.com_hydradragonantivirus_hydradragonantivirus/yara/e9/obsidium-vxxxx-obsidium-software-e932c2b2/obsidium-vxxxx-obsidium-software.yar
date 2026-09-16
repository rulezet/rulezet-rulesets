import "pe"
rule _Obsidium_vxxxx__Obsidium_Software_
{
	meta:
		description = "Obsidium vx.x.x.x -> Obsidium Software"
	strings:
		$0 = {E8 47 19}
	condition:
		$0 at pe.entry_point
}