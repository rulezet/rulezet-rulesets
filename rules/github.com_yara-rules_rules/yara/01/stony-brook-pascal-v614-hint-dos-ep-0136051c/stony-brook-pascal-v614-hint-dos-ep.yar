import "pe"
rule Stony_Brook_Pascal_v614_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 31 ED 9A ?? ?? ?? ?? 55 89 E5 ?? EC ?? ?? 9A }
    condition:
        $a at pe.entry_point

}