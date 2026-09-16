import "pe"
rule MEW_11_SE_v12_NorthfoxHCC: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? 00 }
    condition:
        $a at pe.entry_point

}