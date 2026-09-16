import "pe"
rule Safeguard_10_Simonzh_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 EB 29 }
    condition:
        $a at pe.entry_point

}