import "pe"
rule Microsoft_Visual_Basic_v50: PEiD
{
    strings:
        $a = { 68 }
        $b = { FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}