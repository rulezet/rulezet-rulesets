import "pe"
rule BJFnt_v11b_MARQUiS: PEiD
{
    strings:
        $a = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }
    condition:
        $a at pe.entry_point

}