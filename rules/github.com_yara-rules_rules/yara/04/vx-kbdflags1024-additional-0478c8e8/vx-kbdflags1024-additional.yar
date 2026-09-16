import "pe"
rule Vx_KBDflags1024_additional: PEiD
{
    strings:
        $a = { 8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22 }
    condition:
        $a at pe.entry_point

}