import "pe"
rule NFO_v1x_modified: PEiD
{
    strings:
        $a = { EB 01 9A E8 3D ?? ?? ?? EB 01 9A E8 EB 01 ?? ?? EB 01 9A E8 2C 04 ?? ?? EB }
        $b = { 60 9C 8D 50 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}