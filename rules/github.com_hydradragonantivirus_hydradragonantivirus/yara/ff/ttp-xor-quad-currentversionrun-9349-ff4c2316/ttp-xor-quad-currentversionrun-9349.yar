rule TTP_XOR_QUAD_CurrentVersionRun_9349 {
  strings:
    $key_9349 = { c0 26 [2] e4 28 [2] cf 04 [2] e1 26 [2] f5 3d [2] fa 27 [2] e4 3a [2] e6 3b [2] fd 3d [2] e1 3a [2] fd 15 }

  condition:
    any of them
}