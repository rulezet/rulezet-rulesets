import "pe"
rule tElock_v098: PEiD
{
    strings:
        $a = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E }
    condition:
        $a at pe.entry_point

}