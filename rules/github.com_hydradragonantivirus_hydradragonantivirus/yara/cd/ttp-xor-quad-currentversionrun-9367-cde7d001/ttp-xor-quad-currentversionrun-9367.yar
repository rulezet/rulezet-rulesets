rule TTP_XOR_QUAD_CurrentVersionRun_9367 {
  strings:
    $key_9367 = { c0 08 [2] e4 06 [2] cf 2a [2] e1 08 [2] f5 13 [2] fa 09 [2] e4 14 [2] e6 15 [2] fd 13 [2] e1 14 [2] fd 3b }

  condition:
    any of them
}