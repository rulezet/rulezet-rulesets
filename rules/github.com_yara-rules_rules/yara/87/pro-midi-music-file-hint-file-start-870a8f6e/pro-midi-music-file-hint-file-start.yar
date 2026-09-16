import "pe"
rule PRO_MIDI_Music_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 52 4D 49 44 }
    condition:
        $a at pe.entry_point

}