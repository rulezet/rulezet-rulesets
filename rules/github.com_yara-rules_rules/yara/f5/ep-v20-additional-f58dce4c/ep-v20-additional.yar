import "pe"
rule EP_v20_additional: PEiD
{
    strings:
        $a = { 6A ?? 60 E9 01 01 }
    condition:
        $a at pe.entry_point

}