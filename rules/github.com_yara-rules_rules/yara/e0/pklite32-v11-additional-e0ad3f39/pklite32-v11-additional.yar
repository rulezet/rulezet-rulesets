import "pe"
rule PKLITE32_v11_additional: PEiD
{
    strings:
        $a = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10 }
    condition:
        $a at pe.entry_point

}