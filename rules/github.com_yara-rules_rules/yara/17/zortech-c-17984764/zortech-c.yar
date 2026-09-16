import "pe"
rule Zortech_C: PEiD
{
    strings:
        $a = { FA FC B8 ?? ?? ?? 8C C8 8E D8 }
        $b = { E8 ?? ?? 2E FF ?? ?? ?? FC 06 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}