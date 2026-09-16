import "pe"
rule MPEG_Layer_IIIII_music_file: PEiD
{
    strings:
        $a = { FF F5 }
        $b = { FF F3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}