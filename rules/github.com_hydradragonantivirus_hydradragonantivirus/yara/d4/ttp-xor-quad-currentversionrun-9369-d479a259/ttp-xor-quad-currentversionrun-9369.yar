rule TTP_XOR_QUAD_CurrentVersionRun_9369 {
  strings:
    $key_9369 = { c0 06 [2] e4 08 [2] cf 24 [2] e1 06 [2] f5 1d [2] fa 07 [2] e4 1a [2] e6 1b [2] fd 1d [2] e1 1a [2] fd 35 }

  condition:
    any of them
}