import "pe"
rule Amiga_AIFF_8SFX_Audio_file: PEiD
{
    strings:
        $a = { 46 4F 52 4D ?? ?? ?? ?? 38 53 56 58 56 48 44 52 }
    condition:
        $a at pe.entry_point

}