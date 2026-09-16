import "pe"
rule XMI_music_file_additional: PEiD
{
    strings:
        $a = { 46 4F 52 4D ?? ?? ?? ?? 58 4D 49 44 }
    condition:
        $a at pe.entry_point

}