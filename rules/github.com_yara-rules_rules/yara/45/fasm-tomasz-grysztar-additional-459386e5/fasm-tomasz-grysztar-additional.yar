import "pe"
rule fasm_Tomasz_Grysztar_additional: PEiD
{
    strings:
        $a = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00 }
    condition:
        $a at pe.entry_point

}