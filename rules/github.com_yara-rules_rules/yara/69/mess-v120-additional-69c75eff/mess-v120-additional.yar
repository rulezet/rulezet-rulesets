import "pe"
rule MESS_v120_additional: PEiD
{
    strings:
        $a = { FA B9 ?? ?? F3 ?? ?? E3 ?? EB ?? EB ?? B6 }
    condition:
        $a at pe.entry_point

}