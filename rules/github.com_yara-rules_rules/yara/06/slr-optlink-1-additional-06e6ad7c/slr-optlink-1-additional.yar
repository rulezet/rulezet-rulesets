import "pe"
rule SLR_OPTLINK_1_additional: PEiD
{
    strings:
        $a = { 87 C0 EB ?? 71 ?? 02 D8 }
    condition:
        $a at pe.entry_point

}