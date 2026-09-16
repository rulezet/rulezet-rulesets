import "pe"
rule MASK_v23_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E8 ?? ?? 55 57 CD 03 FC 4D 41 53 4B FA 8B EC 83 ?? ?? ?? FF ?? ?? 5D 49 E8 }
    condition:
        $a at pe.entry_point

}