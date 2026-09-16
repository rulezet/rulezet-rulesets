import "pe"
rule Pksmart_10b_additional: PEiD
{
    strings:
        $a = { BA ?? ?? 8C C8 8B C8 03 C2 81 ?? ?? ?? 51 B9 ?? ?? 51 1E 8C D3 }
    condition:
        $a at pe.entry_point

}