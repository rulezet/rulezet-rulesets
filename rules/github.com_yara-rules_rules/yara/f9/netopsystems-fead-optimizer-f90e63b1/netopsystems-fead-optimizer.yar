import "pe"
rule Netopsystems_FEAD_Optimizer: PEiD
{
    strings:
        $a = { E8 00 00 00 00 58 BB 00 00 40 00 8B }
        $b = { 60 BE 00 50 43 00 8D BE 00 C0 FC FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}