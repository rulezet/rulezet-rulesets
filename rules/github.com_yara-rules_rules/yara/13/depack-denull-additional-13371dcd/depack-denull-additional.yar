import "pe"
rule dePACK_deNULL_additional: PEiD
{
    strings:
        $a = { EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? ?? 00 E8 ?? 00 00 00 }
    condition:
        $a at pe.entry_point

}