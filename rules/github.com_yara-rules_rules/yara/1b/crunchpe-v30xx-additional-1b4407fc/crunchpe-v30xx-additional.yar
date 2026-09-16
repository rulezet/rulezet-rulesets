import "pe"
rule CrunchPE_v30xx_additional: PEiD
{
    strings:
        $a = { 03 D6 B4 40 CD 21 B8 02 42 33 D2 33 C9 CD 21 8B D6 B9 78 01 }
    condition:
        $a at pe.entry_point

}