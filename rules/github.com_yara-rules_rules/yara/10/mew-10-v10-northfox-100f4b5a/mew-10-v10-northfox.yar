import "pe"
rule Mew_10_v10_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 ?? ?? FF FF }
    condition:
        $a at pe.entry_point

}