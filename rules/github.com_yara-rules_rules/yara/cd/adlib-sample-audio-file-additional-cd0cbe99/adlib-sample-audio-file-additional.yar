import "pe"
rule Adlib_Sample_Audio_file_additional: PEiD
{
    strings:
        $a = { 47 4F 4C 44 20 53 41 4D 50 4C 45 }
    condition:
        $a at pe.entry_point

}