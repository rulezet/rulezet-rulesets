import "pe"
rule Zortech_C_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E8 ?? ?? 2E FF ?? ?? ?? FC 06 }
    condition:
        $a at pe.entry_point

}