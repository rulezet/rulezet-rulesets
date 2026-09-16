import "pe"
rule Windows_Group_file: PEiD
{
    strings:
        $a = { 50 4D 43 43 }
    condition:
        $a at pe.entry_point

}