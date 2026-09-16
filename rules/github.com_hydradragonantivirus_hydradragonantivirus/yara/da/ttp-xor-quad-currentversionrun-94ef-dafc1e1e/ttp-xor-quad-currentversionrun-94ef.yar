rule TTP_XOR_QUAD_CurrentVersionRun_94ef {
  strings:
    $key_94ef = { c7 80 [2] e3 8e [2] c8 a2 [2] e6 80 [2] f2 9b [2] fd 81 [2] e3 9c [2] e1 9d [2] fa 9b [2] e6 9c [2] fa b3 }

  condition:
    any of them
}