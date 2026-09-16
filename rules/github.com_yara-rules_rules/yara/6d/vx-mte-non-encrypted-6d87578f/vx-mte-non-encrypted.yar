import "pe"
rule Vx_MTE_non_encrypted: PEiD
{
    strings:
        $a = { F7 D9 80 E1 FE 75 02 49 49 97 A3 ?? ?? 03 C1 24 FE 75 02 48 }
    condition:
        $a at pe.entry_point

}