import "pe"
rule tElock_099_tE: PEiD
{
    strings:
        $a = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 }
    condition:
        $a at pe.entry_point

}