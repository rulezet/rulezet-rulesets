import "pe"
rule BJFnt_v12_RC: PEiD
{
    strings:
        $a = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }
    condition:
        $a at pe.entry_point

}