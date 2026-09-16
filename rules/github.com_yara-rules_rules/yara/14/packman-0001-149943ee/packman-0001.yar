import "pe"
rule Packman_0001: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 58 8D A8 }
    condition:
        $a at pe.entry_point

}