import "pe"
rule Shrink_Wrap_v14: PEiD
{
    strings:
        $a = { 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB }
    condition:
        $a at pe.entry_point

}