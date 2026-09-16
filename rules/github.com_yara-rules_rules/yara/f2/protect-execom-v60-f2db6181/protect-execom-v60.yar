import "pe"
rule PROTECT_EXECOM_v60: PEiD
{
    strings:
        $a = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8 }
    condition:
        $a at pe.entry_point

}