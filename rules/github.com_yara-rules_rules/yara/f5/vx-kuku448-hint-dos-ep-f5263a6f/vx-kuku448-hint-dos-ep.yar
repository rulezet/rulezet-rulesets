import "pe"
rule Vx_Kuku448_Hint_DOS_EP: PEiD
{
    strings:
        $a = { AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB }
    condition:
        $a at pe.entry_point

}