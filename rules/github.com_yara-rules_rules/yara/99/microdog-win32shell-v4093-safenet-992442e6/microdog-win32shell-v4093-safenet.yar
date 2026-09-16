import "pe"
rule MicroDog_Win32Shell_V4093_SafeNet: PEiD
{
    strings:
        $a = { 60 55 8B EC 81 EC 34 04 00 00 53 56 57 C6 85 B8 FE FF FF 00 C6 85 B9 FE FF FF 00 C6 85 BA FE FF FF 00 C6 85 BB FE FF FF 00 8D BD BC FE FF FF 33 C0 B9 3F 00 00 00 F3 AB C6 85 E8 FC FF FF 00 C6 85 E9 FC FF FF 00 C6 85 EA FC FF FF 00 C6 85 EB FC FF FF 00 8D }
    condition:
        $a at pe.entry_point

}