import "pe"
rule PKLITE_v112_v115_v120_2: PEiD
{
    strings:
        $a = { B8 ?? ?? BA ?? ?? 3B C4 73 }
    condition:
        $a at pe.entry_point

}