import "pe"
rule DIET_v100_v100d_Hint_DOS_EP: PEiD
{
    strings:
        $a = { BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }
    condition:
        $a at pe.entry_point

}