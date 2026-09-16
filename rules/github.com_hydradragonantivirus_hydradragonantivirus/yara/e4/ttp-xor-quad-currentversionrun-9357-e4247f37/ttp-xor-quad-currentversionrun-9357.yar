rule TTP_XOR_QUAD_CurrentVersionRun_9357 {
  strings:
    $key_9357 = { c0 38 [2] e4 36 [2] cf 1a [2] e1 38 [2] f5 23 [2] fa 39 [2] e4 24 [2] e6 25 [2] fd 23 [2] e1 24 [2] fd 0b }

  condition:
    any of them
}