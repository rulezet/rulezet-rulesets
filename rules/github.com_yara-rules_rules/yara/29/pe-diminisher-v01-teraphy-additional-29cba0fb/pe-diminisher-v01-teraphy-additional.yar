import "pe"
rule PE_Diminisher_V01_Teraphy_additional: PEiD
{
    strings:
        $a = { 53 51 52 56 57 55 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}