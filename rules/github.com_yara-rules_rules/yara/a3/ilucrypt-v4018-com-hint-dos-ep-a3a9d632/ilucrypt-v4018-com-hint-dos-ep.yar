import "pe"
rule iLUCRYPT_v4018_com_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? 8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 31 05 D1 C8 4F 81 }
    condition:
        $a at pe.entry_point

}