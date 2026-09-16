import "pe"
rule TAV_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E8 ?? ?? 4D 5A CB }
    condition:
        $a at pe.entry_point

}