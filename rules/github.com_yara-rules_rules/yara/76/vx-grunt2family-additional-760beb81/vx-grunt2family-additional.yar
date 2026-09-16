import "pe"
rule Vx_GRUNT2Family_additional: PEiD
{
    strings:
        $a = { 48 E2 F7 C3 51 53 52 E8 DD FF 5A 5B 59 C3 B9 00 00 E2 FE C3 }
    condition:
        $a at pe.entry_point

}