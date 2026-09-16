import "pe"
rule SimplePack_111_Method_2NT_bagieTMX: PEiD
{
    strings:
        $a = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 }
    condition:
        $a at pe.entry_point

}