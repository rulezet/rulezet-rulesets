rule TTP_XOR_QUAD_CurrentVersionRun_947c {
  strings:
    $key_947c = { c7 13 [2] e3 1d [2] c8 31 [2] e6 13 [2] f2 08 [2] fd 12 [2] e3 0f [2] e1 0e [2] fa 08 [2] e6 0f [2] fa 20 }

  condition:
    any of them
}