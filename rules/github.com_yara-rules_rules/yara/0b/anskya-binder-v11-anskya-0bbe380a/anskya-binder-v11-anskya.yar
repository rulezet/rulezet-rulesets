import "pe"
rule Anskya_Binder_v11_Anskya: PEiD
{
    strings:
        $a = { BE ?? ?? ?? 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }
    condition:
        $a at pe.entry_point

}