import "pe"
rule _EXE_Shield_vxx__Exeshield_Corp_
{
	meta:
		description = "EXE Shield vx.x -> Exeshield Corp."
	strings:
		$0 = {65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00}
	condition:
		$0 at pe.entry_point
}