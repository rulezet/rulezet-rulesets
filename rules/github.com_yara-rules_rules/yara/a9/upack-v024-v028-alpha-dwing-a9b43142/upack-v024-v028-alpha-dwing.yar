import "pe"
rule Upack_v024_v028_Alpha_Dwing: PEiD
{
    strings:
        $a = { BE 88 01 40 00 AD ?? ?? 95 AD 91 F3 A5 AD }
    condition:
        $a at pe.entry_point

}