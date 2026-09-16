import "pe"
rule Anskya_Binder_v11_Anskya_additional: PEiD
{
    strings:
        $a = { BE ?? ?? ?? 00 83 C6 01 FF E6 00 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? 02 ?? ?? 00 10 00 00 00 02 00 }
    condition:
        $a at pe.entry_point

}