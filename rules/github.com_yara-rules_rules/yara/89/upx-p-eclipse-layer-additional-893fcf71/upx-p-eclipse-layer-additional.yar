import "pe"
rule UPX_p_ECLiPSE_layer_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }
    condition:
        $a at pe.entry_point

}