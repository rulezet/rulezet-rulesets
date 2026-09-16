import "pe"
rule Microsoft_Visual_C_Basic_NET_additional: PEiD
{
    strings:
        $a = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }
    condition:
        $a at pe.entry_point

}