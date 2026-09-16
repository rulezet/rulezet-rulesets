import "pe"
rule kkrunchy_v017_F_Giesen_additional: PEiD
{
    strings:
        $a = { FC FF 4D 08 31 D2 8D 7D 30 BE }
    condition:
        $a at pe.entry_point

}