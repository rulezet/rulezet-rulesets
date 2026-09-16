import "pe"
rule MIDI_Music_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 4D 54 68 64 00 00 00 06 ?? ?? ?? ?? ?? ?? 4D 54 }
    condition:
        $a at pe.entry_point

}