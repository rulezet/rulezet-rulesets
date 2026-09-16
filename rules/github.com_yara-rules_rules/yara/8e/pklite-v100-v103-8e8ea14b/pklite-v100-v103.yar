import "pe"
rule PKLITE_v100_v103: PEiD
{
    strings:
        $a = { B8 ?? ?? BA ?? ?? 8C DB 03 D8 3B }
    condition:
        $a at pe.entry_point

}