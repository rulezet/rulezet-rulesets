import "pe"
rule CRYPT_Version_17_c_Dismember_EXE_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 0E 17 9C 58 F6 ?? ?? 74 ?? E9 }
    condition:
        $a at pe.entry_point

}