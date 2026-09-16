import "pe"
rule _VBOX_v42_MTE_
{
	meta:
		description = "VBOX v4.2 MTE"
	strings:
		$0 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B}
	condition:
		$0 at pe.entry_point
}