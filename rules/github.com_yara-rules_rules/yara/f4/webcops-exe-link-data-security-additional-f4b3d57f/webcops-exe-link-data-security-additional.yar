import "pe"
rule WebCops_EXE_LINK_Data_Security_additional: PEiD
{
    strings:
        $a = { EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72 }
    condition:
        $a at pe.entry_point

}