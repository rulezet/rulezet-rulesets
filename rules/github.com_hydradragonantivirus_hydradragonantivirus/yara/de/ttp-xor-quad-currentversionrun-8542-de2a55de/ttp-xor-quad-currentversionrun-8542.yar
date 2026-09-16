rule TTP_XOR_QUAD_CurrentVersionRun_8542 {
  strings:
    $key_8542 = { d6 2d [2] f2 23 [2] d9 0f [2] f7 2d [2] e3 36 [2] ec 2c [2] f2 31 [2] f0 30 [2] eb 36 [2] f7 31 [2] eb 1e }

  condition:
    any of them
}