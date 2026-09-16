import "pe"
rule ACProtect_13x_14x_DLL_Risco_Software_Inc: PEiD
{
    strings:
        $a = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 ?? BA ?? ?? CD 21 B8 ?? ?? CD 21 }
        $b = { 80 7C 24 08 01 0F 85 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}