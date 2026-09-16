import "pe"
rule UPX_wwwupxsourceforgenet: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF }
        $b = { 60 BE ?? ?0 ?? 00 8D BE ?? ?? F? FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}