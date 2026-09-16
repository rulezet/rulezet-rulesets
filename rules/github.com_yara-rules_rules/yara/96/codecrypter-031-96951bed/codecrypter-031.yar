import "pe"
rule codeCrypter_031: PEiD
{
    strings:
        $a = { 50 58 53 5B 90 BB ?? ?? 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }
        $b = { 50 58 53 5B 90 BB ?? ?? 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}