import "pe"
rule Special_EXE_Pasword_Protector_V101_Pavol_Cerven: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E }
    condition:
        $a at pe.entry_point

}