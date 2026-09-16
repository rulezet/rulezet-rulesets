import "pe"
rule _Thinstall_vxx_
{
	meta:
		description = "Thinstall vx.x"
	strings:
		$0 = {60 E8 5D 81 ED E8 0D}
	condition:
		$0 at pe.entry_point
}