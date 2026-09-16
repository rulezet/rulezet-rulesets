rule TTP_XOR_QUAD_CurrentVersionRun_8469 {
  strings:
    $key_8469 = { d7 06 [2] f3 08 [2] d8 24 [2] f6 06 [2] e2 1d [2] ed 07 [2] f3 1a [2] f1 1b [2] ea 1d [2] f6 1a [2] ea 35 }

  condition:
    any of them
}