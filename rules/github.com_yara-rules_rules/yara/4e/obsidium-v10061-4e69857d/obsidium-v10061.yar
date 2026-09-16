import "pe"
rule Obsidium_v10061: PEiD
{
    strings:
        $a = { E8 47 }
        $b = { E8 AF 1C 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}