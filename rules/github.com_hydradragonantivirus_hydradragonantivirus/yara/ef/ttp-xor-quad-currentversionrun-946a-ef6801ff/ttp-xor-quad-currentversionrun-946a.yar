rule TTP_XOR_QUAD_CurrentVersionRun_946a {
  strings:
    $key_946a = { c7 05 [2] e3 0b [2] c8 27 [2] e6 05 [2] f2 1e [2] fd 04 [2] e3 19 [2] e1 18 [2] fa 1e [2] e6 19 [2] fa 36 }

  condition:
    any of them
}