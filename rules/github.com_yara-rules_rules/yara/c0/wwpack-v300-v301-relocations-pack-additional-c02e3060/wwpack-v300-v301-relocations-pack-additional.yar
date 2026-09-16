import "pe"
rule WWPACK_v300_v301_Relocations_pack_additional: PEiD
{
    strings:
        $a = { BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC }
    condition:
        $a at pe.entry_point

}