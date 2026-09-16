import "pe"
rule MoleBox_v20_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 60 E8 4F }
    condition:
        $a at pe.entry_point

}