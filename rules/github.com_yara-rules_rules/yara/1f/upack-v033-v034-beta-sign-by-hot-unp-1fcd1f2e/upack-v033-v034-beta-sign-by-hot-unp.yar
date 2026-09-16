import "pe"
rule Upack_v033_v034_Beta_Sign_by_hot_UNP: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }
        $b = { 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}