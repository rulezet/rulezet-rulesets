rule PEiD_01777_PRO_PACK_v2_08__emphasis_on_packed_size__locked_ {
  meta:
    description = "[PRO-PACK v2.08, emphasis on packed size, locked]"
    ep_only     = "true"

  strings:
    $a = { 83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B }

  condition:
    $a
}