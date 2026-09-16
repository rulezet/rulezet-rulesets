import "pe"
rule USERNAME_v300_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? E8 ?? ?? 5D 83 ?? ?? FA FC 33 F6 8E DE BF ?? ?? 03 FD B9 ?? ?? F3 A4 8B FC }
    condition:
        $a at pe.entry_point

}