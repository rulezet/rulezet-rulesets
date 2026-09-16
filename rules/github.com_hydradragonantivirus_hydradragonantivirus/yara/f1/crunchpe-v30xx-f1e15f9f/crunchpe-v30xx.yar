import "pe"
rule _CrunchPE_v30xx_
{
	meta:
		description = "Crunch/PE v3.0.x.x"
	condition:
		uint8(pe.entry_point) == 0xEB
}