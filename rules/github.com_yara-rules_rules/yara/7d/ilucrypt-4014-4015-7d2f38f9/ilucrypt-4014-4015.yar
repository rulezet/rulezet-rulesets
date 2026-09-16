import "pe"
rule iLUCRYPT_4014_4015: PEiD
{
    strings:
        $a = { 8B EC FA C7 46 F7 00 00 42 81 FA 00 00 75 F9 FF 66 F7 }
    condition:
        $a at pe.entry_point

}