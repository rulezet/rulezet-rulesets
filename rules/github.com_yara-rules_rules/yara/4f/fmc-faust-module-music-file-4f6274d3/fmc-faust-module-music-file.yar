import "pe"
rule FMC_Faust_Module_music_file: PEiD
{
    strings:
        $a = { 46 4D 43 21 }
    condition:
        $a at pe.entry_point

}