import "pe"
rule HACKSTOP_v113_DarkStop_v10_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA BD ?? ?? D4 85 4E 32 EB EB }
    condition:
        $a at pe.entry_point

}