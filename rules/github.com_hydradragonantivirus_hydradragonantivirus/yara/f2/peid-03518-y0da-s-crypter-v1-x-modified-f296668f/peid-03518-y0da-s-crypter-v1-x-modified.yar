rule PEiD_03518_y0da_s_Crypter_v1_x___Modified_ {
  meta:
    description = "[y0da's Crypter v1.x / Modified]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7 AC }

  condition:
    $a
}