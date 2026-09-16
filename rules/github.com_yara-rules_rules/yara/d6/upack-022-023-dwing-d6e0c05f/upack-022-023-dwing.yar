import "pe"
rule Upack_022_023_Dwing: PEiD
{
    strings:
        $a = { 6A 07 BE 88 01 40 00 AD }
    condition:
        $a at pe.entry_point

}