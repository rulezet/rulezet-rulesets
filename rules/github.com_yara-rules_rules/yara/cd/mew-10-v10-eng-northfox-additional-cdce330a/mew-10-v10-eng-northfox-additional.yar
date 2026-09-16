import "pe"
rule Mew_10_v10_Eng_Northfox_additional: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? ?? FF }
    condition:
        $a at pe.entry_point

}