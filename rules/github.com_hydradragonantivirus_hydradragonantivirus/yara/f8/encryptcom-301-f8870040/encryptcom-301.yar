import "pe"
rule _ENcryptCOM_301_
{
	meta:
		description = "ENcryptCOM 3.01"
	strings:
		$0 = {B4 30 CD 21 3C 02 77 02 CD 20 B0 4D 6A 64 5A EE}
	condition:
		$0 at pe.entry_point
}