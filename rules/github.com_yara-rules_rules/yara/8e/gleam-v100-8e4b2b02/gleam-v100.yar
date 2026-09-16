import "pe"
rule Gleam_v100: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 60 E8 51 FF FF }
        $b = { 83 EC 0C 53 56 57 E8 24 02 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}