rule TTP_XOR_QUAD_CurrentVersionRun_9352 {
  strings:
    $key_9352 = { c0 3d [2] e4 33 [2] cf 1f [2] e1 3d [2] f5 26 [2] fa 3c [2] e4 21 [2] e6 20 [2] fd 26 [2] e1 21 [2] fd 0e }

  condition:
    any of them
}