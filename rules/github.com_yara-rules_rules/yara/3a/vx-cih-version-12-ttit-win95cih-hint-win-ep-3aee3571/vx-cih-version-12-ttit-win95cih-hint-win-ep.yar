import "pe"
rule Vx_CIH_Version_12_TTIT_WIN95CIH_Hint_WIN_EP: PEiD
{
    strings:
        $a = { 55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D }
    condition:
        $a at pe.entry_point

}