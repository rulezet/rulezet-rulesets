import "pe"
rule Ultra_Compressors_Archive: PEiD
{
    strings:
        $a = { 55 43 32 1A }
    condition:
        $a at pe.entry_point

}