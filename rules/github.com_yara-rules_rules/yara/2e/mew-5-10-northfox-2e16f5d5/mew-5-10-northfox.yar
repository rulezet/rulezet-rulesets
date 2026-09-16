import "pe"
rule MEW_5_10_Northfox: PEiD
{
    strings:
        $a = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 }
    condition:
        $a at pe.entry_point

}