import "pe"
rule PC_Guard_v405d_v410d_v415d_additional: PEiD
{
    strings:
        $a = { FC 55 50 E8 00 00 00 00 5D EB 01 }
    condition:
        $a at pe.entry_point

}