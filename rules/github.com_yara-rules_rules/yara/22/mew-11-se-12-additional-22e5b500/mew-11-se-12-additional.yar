import "pe"
rule MEW_11_SE_12_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? 0C ?? ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}