rule TTP_XOR_QUAD_CurrentVersionRun_9452 {
  strings:
    $key_9452 = { c7 3d [2] e3 33 [2] c8 1f [2] e6 3d [2] f2 26 [2] fd 3c [2] e3 21 [2] e1 20 [2] fa 26 [2] e6 21 [2] fa 0e }

  condition:
    any of them
}