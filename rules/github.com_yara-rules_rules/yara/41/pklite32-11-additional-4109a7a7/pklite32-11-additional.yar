import "pe"
rule PKLITE32_11_additional: PEiD
{
    strings:
        $a = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }
    condition:
        $a at pe.entry_point

}