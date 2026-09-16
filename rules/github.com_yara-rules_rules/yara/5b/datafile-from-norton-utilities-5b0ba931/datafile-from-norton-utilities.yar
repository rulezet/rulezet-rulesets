import "pe"
rule Datafile_from_Norton_Utilities: PEiD
{
    strings:
        $a = { 50 4E 43 49 }
    condition:
        $a at pe.entry_point

}