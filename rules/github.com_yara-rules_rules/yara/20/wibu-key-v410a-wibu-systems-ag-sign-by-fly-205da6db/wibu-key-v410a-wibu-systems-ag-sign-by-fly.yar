import "pe"
rule WIBU_Key_V410A_WIBU_SYSTEMS_AG_Sign_by_fly: PEiD
{
    strings:
        $a = { F7 05 ?? ?? ?? ?? FF 00 00 00 75 12 }
    condition:
        $a at pe.entry_point

}