import "pe"
rule MicroJoiner_16_coban2k_additional: PEiD
{
    strings:
        $a = { 33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B }
    condition:
        $a at pe.entry_point

}