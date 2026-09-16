import "pe"
rule Upack_01x_Dwing: PEiD
{
    strings:
        $a = { BE 48 01 40 00 AD 8B F8 }
    condition:
        $a at pe.entry_point

}