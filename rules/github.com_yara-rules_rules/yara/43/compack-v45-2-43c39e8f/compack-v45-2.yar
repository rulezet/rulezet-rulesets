import "pe"
rule COMPACK_v45_2: PEiD
{
    strings:
        $a = { BE ?? ?? E8 ?? ?? 5D 83 ?? ?? 55 50 53 51 52 0E 07 0E 1F 8B CE }
    condition:
        $a at pe.entry_point

}