rule TTP_XOR_QUAD_CurrentVersionRun_96a2 {
  strings:
    $key_96a2 = { c5 cd [2] e1 c3 [2] ca ef [2] e4 cd [2] f0 d6 [2] ff cc [2] e1 d1 [2] e3 d0 [2] f8 d6 [2] e4 d1 [2] f8 fe }

  condition:
    any of them
}