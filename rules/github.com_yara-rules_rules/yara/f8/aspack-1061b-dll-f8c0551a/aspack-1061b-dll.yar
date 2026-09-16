import "pe"
rule ASPack_1061b_DLL: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED EA A8 43 00 B8 E4 A8 43 00 03 C5 2B 85 78 AD 43 00 89 85 84 AD 43 00 80 BD 6E AD 43 00 00 75 15 FE 85 6E AD 43 00 E8 1D 00 00 00 E8 73 02 00 00 E8 0A 03 00 00 8B 85 70 AD 43 00 03 85 84 AD 43 00 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}