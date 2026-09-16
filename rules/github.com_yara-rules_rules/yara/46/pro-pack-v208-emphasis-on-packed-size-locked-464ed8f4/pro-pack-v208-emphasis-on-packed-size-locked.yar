import "pe"
rule PRO_PACK_v208_emphasis_on_packed_size_locked: PEiD
{
    strings:
        $a = { 83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B }
    condition:
        $a at pe.entry_point

}