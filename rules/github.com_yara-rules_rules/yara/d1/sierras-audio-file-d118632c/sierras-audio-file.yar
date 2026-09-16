import "pe"
rule Sierras_audio_file: PEiD
{
    strings:
        $a = { 8D 0C 53 4F 4C 00 22 56 0D }
    condition:
        $a at pe.entry_point

}