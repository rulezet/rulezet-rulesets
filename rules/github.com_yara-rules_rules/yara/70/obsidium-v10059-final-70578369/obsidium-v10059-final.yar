import "pe"
rule Obsidium_v10059_Final: PEiD
{
    strings:
        $a = { E8 AF }
        $b = { E8 AB 1C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}