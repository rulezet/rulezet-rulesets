rule TTP_XOR_QUAD_CurrentVersionRun_94ec {
  strings:
    $key_94ec = { c7 83 [2] e3 8d [2] c8 a1 [2] e6 83 [2] f2 98 [2] fd 82 [2] e3 9f [2] e1 9e [2] fa 98 [2] e6 9f [2] fa b0 }

  condition:
    any of them
}