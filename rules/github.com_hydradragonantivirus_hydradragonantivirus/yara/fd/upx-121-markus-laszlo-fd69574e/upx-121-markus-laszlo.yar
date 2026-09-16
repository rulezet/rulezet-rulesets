import "pe"
rule _UPX_121__Markus__Laszlo_
{
	meta:
		description = "UPX 1.21 -> Markus & Laszlo"
	strings:
		$0 = {31 2E 32 31 00 55 50 58}
	condition:
		$0 at pe.entry_point
}