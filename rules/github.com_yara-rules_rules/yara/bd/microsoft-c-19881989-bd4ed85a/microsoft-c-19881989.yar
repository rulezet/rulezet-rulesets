import "pe"
rule Microsoft_C_19881989: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 02 73 ?? CD 20 BF ?? ?? 8B ?? ?? ?? 2B F7 81 ?? ?? ?? 72 }
    condition:
        $a at pe.entry_point

}