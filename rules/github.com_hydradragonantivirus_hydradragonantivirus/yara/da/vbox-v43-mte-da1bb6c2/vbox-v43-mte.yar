import "pe"
rule _VBOX_v43_MTE_
{
	meta:
		description = "VBOX v4.3 MTE"
	strings:
		$0 = {36 3E 26 8A C0 60}
	condition:
		$0 at pe.entry_point
}