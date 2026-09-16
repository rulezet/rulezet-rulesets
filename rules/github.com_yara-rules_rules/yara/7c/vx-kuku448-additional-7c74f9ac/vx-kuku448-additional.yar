import "pe"
rule Vx_Kuku448_additional: PEiD
{
    strings:
        $a = { AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB }
    condition:
        $a at pe.entry_point

}