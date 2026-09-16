import "pe"
rule tElock_V099_V10_Private_tE: PEiD
{
    strings:
        $a = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}