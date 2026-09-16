import "pe"
rule Possibly_PCX_graphics_format: PEiD
{
    strings:
        $a = { 10 ?? 01 }
        $b = { 0A ?? 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}