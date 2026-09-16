import "pe"
rule Obsidium_vxxxx: PEiD
{
    strings:
        $a = { E9 5D 01 ?? ?? CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 }
        $b = { E8 47 19 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}