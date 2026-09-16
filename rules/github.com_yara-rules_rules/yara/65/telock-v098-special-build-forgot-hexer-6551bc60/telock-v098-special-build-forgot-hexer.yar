import "pe"
rule tElock_V098_Special_Build_forgot_heXer: PEiD
{
    strings:
        $a = { E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA }
    condition:
        $a at pe.entry_point

}