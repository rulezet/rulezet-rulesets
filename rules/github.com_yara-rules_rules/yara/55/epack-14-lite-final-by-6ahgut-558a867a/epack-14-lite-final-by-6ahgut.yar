import "pe"
rule EPack_14_lite_final_by_6aHguT: PEiD
{
    strings:
        $a = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}