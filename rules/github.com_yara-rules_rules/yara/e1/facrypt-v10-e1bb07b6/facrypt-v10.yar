import "pe"
rule FACRYPT_v10: PEiD
{
    strings:
        $a = { B9 ?? ?? B3 ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3 }
    condition:
        $a at pe.entry_point

}