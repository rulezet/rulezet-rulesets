import "pe"
rule UPX_v103_v104_Modified: PEiD
{
    strings:
        $a = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }
    condition:
        $a at pe.entry_point

}