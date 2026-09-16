import "pe"
rule UPolyX_delikon: PEiD
{
    strings:
        $a = { FF 96 ?? ?? ?? 00 61 E9 ?? ?? ?? FF }
    condition:
        $a at pe.entry_point

}