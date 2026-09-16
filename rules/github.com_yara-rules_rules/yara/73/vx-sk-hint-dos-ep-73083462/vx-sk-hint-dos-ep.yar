import "pe"
rule Vx_SK_Hint_DOS_EP: PEiD
{
    strings:
        $a = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09 }
    condition:
        $a at pe.entry_point

}