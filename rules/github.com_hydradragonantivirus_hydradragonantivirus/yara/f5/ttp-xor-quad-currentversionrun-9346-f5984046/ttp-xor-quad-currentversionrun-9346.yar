rule TTP_XOR_QUAD_CurrentVersionRun_9346 {
  strings:
    $key_9346 = { c0 29 [2] e4 27 [2] cf 0b [2] e1 29 [2] f5 32 [2] fa 28 [2] e4 35 [2] e6 34 [2] fd 32 [2] e1 35 [2] fd 1a }

  condition:
    any of them
}