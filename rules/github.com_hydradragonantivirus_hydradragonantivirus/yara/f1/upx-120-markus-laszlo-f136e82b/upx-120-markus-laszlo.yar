import "pe"
rule _UPX_120__Markus__Laszlo_
{
	meta:
		description = "UPX 1.20 -> Markus & Laszlo"
	strings:
		$0 = {31 2E 32 30 00 55 50 58}
	condition:
		$0 at pe.entry_point
}