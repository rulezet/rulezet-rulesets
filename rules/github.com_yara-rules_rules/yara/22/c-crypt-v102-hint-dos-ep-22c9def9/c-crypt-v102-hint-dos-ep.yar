import "pe"
rule C_Crypt_v102_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? E8 ?? ?? 5D 83 ?? ?? 55 D9 D0 9C 58 25 ?? ?? 50 9D 50 57 BF ?? ?? B0 ?? AA 5F 58 66 51 }
    condition:
        $a at pe.entry_point

}