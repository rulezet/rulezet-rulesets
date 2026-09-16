import "pe"
rule MacroMedia_ShockWave_Movie_file: PEiD
{
    strings:
        $a = { 46 57 53 }
    condition:
        $a at pe.entry_point

}