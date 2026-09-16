rule TTP_XOR_QUAD_CurrentVersionRun_947d {
  strings:
    $key_947d = { c7 12 [2] e3 1c [2] c8 30 [2] e6 12 [2] f2 09 [2] fd 13 [2] e3 0e [2] e1 0f [2] fa 09 [2] e6 0e [2] fa 21 }

  condition:
    any of them
}