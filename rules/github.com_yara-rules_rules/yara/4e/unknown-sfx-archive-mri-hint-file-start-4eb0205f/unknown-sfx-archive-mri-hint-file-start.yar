import "pe"
rule Unknown_SFX_Archive_MRI_Hint_FILE_START: PEiD
{
    strings:
        $a = { 4D 52 49 }
    condition:
        $a at pe.entry_point

}