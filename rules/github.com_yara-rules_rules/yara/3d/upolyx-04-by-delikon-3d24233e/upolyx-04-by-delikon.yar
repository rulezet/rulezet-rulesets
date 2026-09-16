import "pe"
rule UPolyx_04_by_delikon: PEiD
{
    strings:
        $a = { C3 ?? ?? ?? ?? ?? 83 EC 04 89 }
    condition:
        $a at pe.entry_point

}