import "pe"
rule Vx_Modification_of_Hi924_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB ?? ?? 26 ?? ?? 49 48 5B }
    condition:
        $a at pe.entry_point

}