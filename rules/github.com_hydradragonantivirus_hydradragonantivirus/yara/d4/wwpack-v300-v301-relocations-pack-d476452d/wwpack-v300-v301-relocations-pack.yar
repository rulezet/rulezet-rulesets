import "pe"
rule _WWPACK_v300_v301_Relocations_pack_
{
	meta:
		description = "WWPACK v3.00, v3.01 (Relocations pack)"
	strings:
		$0 = {BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC}
	condition:
		$0 at pe.entry_point
}