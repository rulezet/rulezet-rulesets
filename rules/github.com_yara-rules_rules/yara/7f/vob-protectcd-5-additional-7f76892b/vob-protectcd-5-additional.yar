import "pe"
rule VOB_ProtectCD_5_additional: PEiD
{
    strings:
        $a = { 36 3E 26 8A C0 60 E8 }
    condition:
        $a at pe.entry_point

}