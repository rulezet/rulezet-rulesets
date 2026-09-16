import "pe"
rule _SciFax_Graphics_file_
{
	meta:
		description = "SciFax Graphics file"
	strings:
		$0 = {44 54 3D 00}
	condition:
		$0 at pe.entry_point
}