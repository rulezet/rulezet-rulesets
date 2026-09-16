import "pe"
rule tElock_v070: PEiD
{
    strings:
        $a = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }
    condition:
        $a at pe.entry_point

}