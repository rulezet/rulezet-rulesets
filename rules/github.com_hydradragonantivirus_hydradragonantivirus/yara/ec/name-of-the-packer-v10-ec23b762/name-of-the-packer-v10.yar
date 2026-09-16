import "pe"
rule _Name_of_the_Packer_v10_
{
	meta:
		description = "Name of the Packer v1.0"
	strings:
		$0 = {50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3}
	condition:
		$0 at pe.entry_point
}