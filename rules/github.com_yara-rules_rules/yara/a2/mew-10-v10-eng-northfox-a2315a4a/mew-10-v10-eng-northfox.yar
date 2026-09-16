import "pe"
rule Mew_10_V10_Eng_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF }
    condition:
        $a at pe.entry_point

}