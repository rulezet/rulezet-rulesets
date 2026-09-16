import "pe"
rule PRO_PACK_v2_08__emphasis_on_packed_size__locked {
  strings:
    $a0 = { 83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B }

  condition:
    $a0 at pe.entry_point
}