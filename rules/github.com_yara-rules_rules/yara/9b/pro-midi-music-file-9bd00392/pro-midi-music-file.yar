import "pe"
rule PRO_MIDI_Music_file: PEiD
{
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 52 4D 49 44 }
    condition:
        $a at pe.entry_point

}