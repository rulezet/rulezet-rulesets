import "pe"
rule MEW_5_Northfox: PEiD
{
    strings:
        $a = { BE ?? ?? ?? ?? AD 91 AD 93 53 AD 96 56 5F AC }
    condition:
        $a at pe.entry_point

}