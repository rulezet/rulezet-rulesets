import "pe"
rule PECompact_v184: PEiD
{
    strings:
        $a = { 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }
    condition:
        $a at pe.entry_point

}