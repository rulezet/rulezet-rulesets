import "pe"
rule Creative_Audio_file: PEiD
{
    strings:
        $a = { 43 72 65 61 74 69 76 65 20 56 6F 69 63 65 20 46 69 6C 65 }
    condition:
        $a at pe.entry_point

}