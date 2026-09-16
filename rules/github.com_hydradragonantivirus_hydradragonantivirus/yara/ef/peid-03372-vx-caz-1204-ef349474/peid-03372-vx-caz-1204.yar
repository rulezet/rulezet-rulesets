rule PEiD_03372_Vx__Caz_1204_ {
  meta:
    description = "[Vx: Caz.1204]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10 }

  condition:
    $a
}