rule PEiD_00496_dUP_2_x_Patcher____www_diablo2oo2_cjb_net_ {
  meta:
    description = "[dUP 2.x Patcher -> www.diablo2oo2.cjb.net]"
    ep_only     = "false"

  strings:
    $a = { 8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9 }

  condition:
    $a
}