rule PEiD_00896_hying_s_PE_Armor____hying_CCG_ {
  meta:
    description = "[hying's PE-Armor -> hying[CCG]"
    ep_only     = "true"

  strings:
    $a = { E8 AA 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D }

  condition:
    $a
}