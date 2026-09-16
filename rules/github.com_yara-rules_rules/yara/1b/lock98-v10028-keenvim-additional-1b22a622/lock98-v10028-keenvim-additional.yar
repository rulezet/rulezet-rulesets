import "pe"
rule LOCK98_V10028_keenvim_additional: PEiD
{
    strings:
        $a = { 55 E8 00 00 00 00 5D 81 ?? ?? ?? ?? ?? EB 05 E9 ?? ?? ?? ?? EB 08 }
    condition:
        $a at pe.entry_point

}