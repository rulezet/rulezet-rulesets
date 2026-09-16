import "pe"
rule VOB_ProtectCD_5: PEiD
{
    strings:
        $a = { 5F 81 EF BE 40 8B 87 03 C6 57 56 8C A7 FF 10 89 87 5E }
        $b = { 36 3E 26 8A C0 60 E8 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}