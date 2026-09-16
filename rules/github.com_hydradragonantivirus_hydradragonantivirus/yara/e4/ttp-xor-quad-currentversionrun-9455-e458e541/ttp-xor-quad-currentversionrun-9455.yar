rule TTP_XOR_QUAD_CurrentVersionRun_9455 {
  strings:
    $key_9455 = { c7 3a [2] e3 34 [2] c8 18 [2] e6 3a [2] f2 21 [2] fd 3b [2] e3 26 [2] e1 27 [2] fa 21 [2] e6 26 [2] fa 09 }

  condition:
    any of them
}