import "pe"
rule WATCOM_CCpp_Open_Watcom: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? 00 ?? ?? ?? 00 57 41 }
    condition:
        $a at pe.entry_point

}