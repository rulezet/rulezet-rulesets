import "pe"
rule Real_Networks_VideoAudio_file: PEiD
{
    strings:
        $a = { 2E 52 4D 46 }
    condition:
        $a at pe.entry_point

}