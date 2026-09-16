import "pe"
rule ComCrypt_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? B9 ?? ?? BE ?? ?? 89 F7 0E 1F 0E 07 BB ?? ?? FC AD 31 D8 AB E2 ?? C6 }
    condition:
        $a at pe.entry_point

}