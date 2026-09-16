import "pe"
rule MCLock_v12_v13_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? 90 90 90 FA 29 C0 8E C0 26 C6 06 }
    condition:
        $a at pe.entry_point

}