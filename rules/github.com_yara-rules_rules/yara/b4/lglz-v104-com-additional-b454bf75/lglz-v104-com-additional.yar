import "pe"
rule LGLZ_v104_com_additional: PEiD
{
    strings:
        $a = { BF ?? ?? 3B FC 72 19 B4 09 BA 12 01 CD 21 B4 4C CD 21 }
    condition:
        $a at pe.entry_point

}