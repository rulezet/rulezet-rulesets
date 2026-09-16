import "pe"
rule Upack_v02Beta: PEiD
{
    strings:
        $a = { BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33 }
    condition:
        $a at pe.entry_point

}