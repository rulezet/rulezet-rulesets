import "pe"
rule tElock_099_10_private_tE: PEiD
{
    strings:
        $a = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}