import "pe"
rule AMGC_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { AD 36 22 00 }
    condition:
        $a at pe.entry_point

}