import "pe"
rule Copy_Protector_v20_Hint_DOS_EP_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? 50 53 51 52 1E 06 57 E8 ?? ?? 5F 83 EF ?? B4 ?? 1E 0E 1F }
    condition:
        $a at pe.entry_point

}