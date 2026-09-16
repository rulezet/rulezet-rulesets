rule TTP_XOR_QUAD_CurrentVersionRun_9475 {
  strings:
    $key_9475 = { c7 1a [2] e3 14 [2] c8 38 [2] e6 1a [2] f2 01 [2] fd 1b [2] e3 06 [2] e1 07 [2] fa 01 [2] e6 06 [2] fa 29 }

  condition:
    any of them
}