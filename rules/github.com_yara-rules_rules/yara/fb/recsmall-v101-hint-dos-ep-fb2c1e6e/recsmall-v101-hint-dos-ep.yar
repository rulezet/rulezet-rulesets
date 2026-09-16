import "pe"
rule RECSmall_v101_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 8C D8 1E E8 ?? ?? 5D 83 ?? ?? 81 ?? ?? ?? B9 ?? ?? 40 8E D8 2B DB B2 55 }
    condition:
        $a at pe.entry_point

}