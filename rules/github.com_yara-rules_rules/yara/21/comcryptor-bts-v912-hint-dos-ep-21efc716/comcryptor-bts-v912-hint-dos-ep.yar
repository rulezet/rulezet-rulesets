import "pe"
rule ComCryptor_BTS_v912_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? B7 ?? E8 ?? ?? 83 ?? ?? EB ?? 5D 55 C3 BF ?? ?? 03 FD 8B F7 B9 }
    condition:
        $a at pe.entry_point

}