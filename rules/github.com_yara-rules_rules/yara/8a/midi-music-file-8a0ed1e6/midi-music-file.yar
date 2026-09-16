import "pe"
rule MIDI_Music_file: PEiD
{
    strings:
        $a = { 4D 54 68 64 00 00 00 06 ?? ?? ?? ?? ?? ?? 4D 54 }
    condition:
        $a at pe.entry_point

}