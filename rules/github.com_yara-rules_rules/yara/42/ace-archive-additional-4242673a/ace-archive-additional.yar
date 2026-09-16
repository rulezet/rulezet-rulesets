import "pe"
rule ACE_Archive_additional: PEiD
{
    strings:
        $a = { 2A 2A 41 43 45 2A 2A }
    condition:
        $a at pe.entry_point

}