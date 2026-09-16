rule PEiD_03414_Vx__SK_ {
  meta:
    description = "[Vx: SK]"
    ep_only     = "true"

  strings:
    $a = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09 }

  condition:
    $a
}