import "pe"
rule Unknown_SFX_Archive_IDSKA32_Hint_FILE_START: PEiD
{
    strings:
        $a = { 69 64 73 6B 61 33 32 }
    condition:
        $a at pe.entry_point

}