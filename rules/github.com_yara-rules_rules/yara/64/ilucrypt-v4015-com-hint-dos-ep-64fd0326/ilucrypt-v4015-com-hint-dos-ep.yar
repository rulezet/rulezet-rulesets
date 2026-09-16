import "pe"
rule ILUCRYPT_v4015_com_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? 8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7 }
    condition:
        $a at pe.entry_point

}