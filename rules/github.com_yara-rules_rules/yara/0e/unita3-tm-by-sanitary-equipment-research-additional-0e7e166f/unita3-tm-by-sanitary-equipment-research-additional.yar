import "pe"
rule UNITA3_tm_by_Sanitary_Equipment_Research_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 4D 5A 3E }
    condition:
        $a at pe.entry_point

}