import "pe"
rule Turbo_Pascal_v55_Unit_Hint_FILE_START: PEiD
{
    strings:
        $a = { 54 50 55 36 00 }
    condition:
        $a at pe.entry_point

}