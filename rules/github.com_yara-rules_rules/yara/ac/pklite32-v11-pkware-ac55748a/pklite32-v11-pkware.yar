import "pe"
rule PKLITE32_v11_PKWare: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 00 00 00 E8 }
    condition:
        $a at pe.entry_point

}