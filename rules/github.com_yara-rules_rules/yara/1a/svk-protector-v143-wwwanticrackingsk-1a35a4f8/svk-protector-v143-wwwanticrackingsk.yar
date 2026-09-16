import "pe"
rule SVK_Protector_v143_wwwanticrackingsk: PEiD
{
    strings:
        $a = { 78 4E 88 4C 0E B0 3C 78 4E 97 56 7B 94 90 00 00 08 DB 5C 50 20 00 05 }
        $b = { 78 4E 88 4C 0E B0 3C 78 4E 97 56 7B 94 90 00 00 08 DB 5C 50 20 00 05 6? }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}