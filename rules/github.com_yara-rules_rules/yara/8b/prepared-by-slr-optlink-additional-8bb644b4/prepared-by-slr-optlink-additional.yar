import "pe"
rule Prepared_by_SLR_OPTLINK_additional: PEiD
{
    strings:
        $a = { 87 C0 55 56 57 52 51 53 50 9C FC 8C DA 83 ?? ?? 16 07 0E 1F }
    condition:
        $a at pe.entry_point

}