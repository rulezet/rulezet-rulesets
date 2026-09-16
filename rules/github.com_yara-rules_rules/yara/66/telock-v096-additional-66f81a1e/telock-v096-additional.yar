import "pe"
rule tElock_v096_additional: PEiD
{
    strings:
        $a = { E9 53 00 FF FD FF FB FF F9 FF BC 03 00 8B E5 4C 4C C3 }
    condition:
        $a at pe.entry_point

}