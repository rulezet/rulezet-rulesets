import "pe"
rule ChSfx_small_v11: PEiD
{
    strings:
        $a = { BA ?? ?? E8 ?? ?? 8B EC 83 EC ?? 8C C8 BB ?? ?? B1 ?? D3 EB 03 C3 8E D8 05 ?? ?? 89 }
    condition:
        $a at pe.entry_point

}