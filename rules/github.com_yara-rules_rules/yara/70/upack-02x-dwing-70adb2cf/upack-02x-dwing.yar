import "pe"
rule Upack_02x_Dwing: PEiD
{
    strings:
        $a = { BE 88 01 40 00 AD 8B F8 }
    condition:
        $a at pe.entry_point

}