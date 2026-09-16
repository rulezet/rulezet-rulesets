rule TTP_XOR_QUAD_CurrentVersionRun_968a {
  strings:
    $key_968a = { c5 e5 [2] e1 eb [2] ca c7 [2] e4 e5 [2] f0 fe [2] ff e4 [2] e1 f9 [2] e3 f8 [2] f8 fe [2] e4 f9 [2] f8 d6 }

  condition:
    any of them
}