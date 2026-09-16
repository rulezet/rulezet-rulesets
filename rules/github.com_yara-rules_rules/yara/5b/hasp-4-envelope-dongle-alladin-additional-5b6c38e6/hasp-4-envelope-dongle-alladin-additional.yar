import "pe"
rule Hasp_4_envelope_dongle_Alladin_additional: PEiD
{
    strings:
        $a = { 10 02 D0 51 0F 00 83 }
    condition:
        $a at pe.entry_point

}