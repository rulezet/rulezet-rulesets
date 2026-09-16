import "pe"
rule Mew_11_SE_v12_Eng_Northfox: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C }
    condition:
        $a at pe.entry_point

}