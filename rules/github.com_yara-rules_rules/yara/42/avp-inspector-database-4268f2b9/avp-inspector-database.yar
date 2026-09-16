import "pe"
rule AVP_Inspector_Database: PEiD
{
    strings:
        $a = { 47 68 6F 73 74 20 42 75 73 74 65 72 }
    condition:
        $a at pe.entry_point

}