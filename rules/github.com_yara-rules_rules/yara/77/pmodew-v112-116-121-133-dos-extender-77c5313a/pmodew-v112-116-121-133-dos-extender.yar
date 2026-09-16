import "pe"
rule PMODEW_v112_116_121_133_DOS_extender: PEiD
{
    strings:
        $a = { FC 16 07 BF ?? ?? 8B F7 57 B9 ?? ?? F3 A5 06 1E 07 1F 5F BE ?? ?? 06 0E A4 }
    condition:
        $a at pe.entry_point

}