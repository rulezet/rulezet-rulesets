import "pe"
rule id_Softwares_WAD_file: PEiD
{
    strings:
        $a = { 50 57 41 44 0B 00 }
    condition:
        $a at pe.entry_point

}