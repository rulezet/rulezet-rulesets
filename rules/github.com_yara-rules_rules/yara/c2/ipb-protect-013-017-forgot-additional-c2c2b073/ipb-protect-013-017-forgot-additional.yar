import "pe"
rule iPB_Protect_013_017_forgot_additional: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 }
    condition:
        $a at pe.entry_point

}