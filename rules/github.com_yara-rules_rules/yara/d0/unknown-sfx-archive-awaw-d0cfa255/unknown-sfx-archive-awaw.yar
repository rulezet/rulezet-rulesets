import "pe"
rule Unknown_SFX_Archive_aWAW: PEiD
{
    strings:
        $a = { 61 57 41 57 }
    condition:
        $a at pe.entry_point

}