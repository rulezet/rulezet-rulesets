import "pe"
rule Turbo_C_1987: PEiD
{
    strings:
        $a = { FB BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 }
        $b = { FB 8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}