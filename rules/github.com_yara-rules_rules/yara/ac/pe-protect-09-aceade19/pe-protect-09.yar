import "pe"
rule PE_Protect_09: PEiD
{
    strings:
        $a = { E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F }
    condition:
        $a at pe.entry_point

}