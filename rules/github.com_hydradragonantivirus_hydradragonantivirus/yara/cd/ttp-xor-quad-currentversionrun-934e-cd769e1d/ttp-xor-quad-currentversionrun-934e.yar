rule TTP_XOR_QUAD_CurrentVersionRun_934e {
  strings:
    $key_934e = { c0 21 [2] e4 2f [2] cf 03 [2] e1 21 [2] f5 3a [2] fa 20 [2] e4 3d [2] e6 3c [2] fd 3a [2] e1 3d [2] fd 12 }

  condition:
    any of them
}