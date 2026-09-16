import "pe"
rule VC8_Microsoft_Corporation: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? E9 ?? ?? FF FF }
    condition:
        $a at pe.entry_point

}