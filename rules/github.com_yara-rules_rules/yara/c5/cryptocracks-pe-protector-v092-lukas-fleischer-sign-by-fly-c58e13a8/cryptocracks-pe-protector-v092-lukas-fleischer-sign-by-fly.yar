import "pe"
rule CRYPToCRACks_PE_Protector_V092_Lukas_Fleischer_Sign_by_fly: PEiD
{
    strings:
        $a = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26 }
    condition:
        $a at pe.entry_point

}