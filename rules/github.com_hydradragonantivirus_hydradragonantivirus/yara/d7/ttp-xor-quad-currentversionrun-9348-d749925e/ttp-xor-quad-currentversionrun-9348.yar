rule TTP_XOR_QUAD_CurrentVersionRun_9348 {
  strings:
    $key_9348 = { c0 27 [2] e4 29 [2] cf 05 [2] e1 27 [2] f5 3c [2] fa 26 [2] e4 3b [2] e6 3a [2] fd 3c [2] e1 3b [2] fd 14 }

  condition:
    any of them
}