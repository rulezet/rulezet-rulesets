import "pe"
rule RAR_SFX_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 00 00 00 00 90 }
    condition:
        $a at pe.entry_point

}