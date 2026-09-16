import "pe"
rule Can2Exe_v001: PEiD
{
    strings:
        $a = { 0E 1F 0E 07 E8 ?? ?? E8 ?? ?? 3A C6 73 }
    condition:
        $a at pe.entry_point

}