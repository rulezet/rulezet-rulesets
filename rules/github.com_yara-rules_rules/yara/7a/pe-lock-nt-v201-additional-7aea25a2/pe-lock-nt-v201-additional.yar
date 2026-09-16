import "pe"
rule PE_Lock_NT_v201_additional: PEiD
{
    strings:
        $a = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 }
    condition:
        $a at pe.entry_point

}