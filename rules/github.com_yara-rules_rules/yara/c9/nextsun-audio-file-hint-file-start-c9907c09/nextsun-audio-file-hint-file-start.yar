import "pe"
rule NextSun_Audio_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 2E 73 6E 64 }
    condition:
        $a at pe.entry_point

}