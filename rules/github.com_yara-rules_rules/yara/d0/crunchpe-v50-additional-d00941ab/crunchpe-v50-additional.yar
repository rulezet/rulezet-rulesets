import "pe"
rule CrunchPE_v50_additional: PEiD
{
    strings:
        $a = { EB 15 03 ?? ?? ?? 06 }
    condition:
        $a at pe.entry_point

}