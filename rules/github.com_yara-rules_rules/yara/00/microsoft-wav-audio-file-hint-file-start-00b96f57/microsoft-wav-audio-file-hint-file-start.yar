import "pe"
rule Microsoft_WAV_Audio_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 57 41 56 45 66 6D 74 }
    condition:
        $a at pe.entry_point

}