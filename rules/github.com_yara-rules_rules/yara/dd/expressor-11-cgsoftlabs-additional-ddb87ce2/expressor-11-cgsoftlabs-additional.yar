import "pe"
rule eXPressor_11_CGSoftLabs_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}