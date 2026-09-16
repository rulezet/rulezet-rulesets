import "pe"
rule UPolyx_05_by_delikon: PEiD
{
    strings:
        $a = { 51 ?? C9 B9 ?? ?? ?? ?? 83 ?? 01 E2 }
    condition:
        $a at pe.entry_point

}