import "pe"
rule Vx_Necropolis_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 50 FC AD 33 C2 AB 8B D0 E2 F8 }
    condition:
        $a at pe.entry_point

}