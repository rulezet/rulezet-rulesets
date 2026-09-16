import "pe"
rule HACKSTOP_v100_additional: PEiD
{
    strings:
        $a = { FA BD ?? ?? FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F }
    condition:
        $a at pe.entry_point

}