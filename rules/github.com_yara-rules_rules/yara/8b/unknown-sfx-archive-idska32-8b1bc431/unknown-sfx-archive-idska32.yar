import "pe"
rule Unknown_SFX_Archive_IDSKA32: PEiD
{
    strings:
        $a = { 69 64 73 6B 61 33 32 }
    condition:
        $a at pe.entry_point

}