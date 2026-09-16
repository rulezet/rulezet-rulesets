import "pe"
rule Upack_v01x_v02x_Dwing: PEiD
{
    strings:
        $a = { BE 88 01 ?? ?? AD 8B F8 95 }
    condition:
        $a at pe.entry_point

}