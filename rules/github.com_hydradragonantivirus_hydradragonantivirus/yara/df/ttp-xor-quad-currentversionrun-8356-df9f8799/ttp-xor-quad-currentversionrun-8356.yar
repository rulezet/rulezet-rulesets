rule TTP_XOR_QUAD_CurrentVersionRun_8356 {
  strings:
    $key_8356 = { d0 39 [2] f4 37 [2] df 1b [2] f1 39 [2] e5 22 [2] ea 38 [2] f4 25 [2] f6 24 [2] ed 22 [2] f1 25 [2] ed 0a }

  condition:
    any of them
}