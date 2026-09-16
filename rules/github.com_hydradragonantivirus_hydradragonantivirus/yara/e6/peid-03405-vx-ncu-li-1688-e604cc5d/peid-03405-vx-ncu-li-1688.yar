rule PEiD_03405_Vx__Ncu_Li_1688_ {
  meta:
    description = "[Vx: Ncu-Li.1688]"
    ep_only     = "true"

  strings:
    $a = { 0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8 }

  condition:
    $a
}