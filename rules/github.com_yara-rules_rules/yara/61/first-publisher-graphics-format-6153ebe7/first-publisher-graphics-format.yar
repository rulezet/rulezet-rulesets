import "pe"
rule First_Publisher_Graphics_format: PEiD
{
    strings:
        $a = { 00 00 ?? 01 00 00 ?? 02 }
        $b = { 00 00 ?? 00 00 00 ?? 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}