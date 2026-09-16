rule TTP_XOR_QUAD_CurrentVersionRun_8446 {
  strings:
    $key_8446 = { d7 29 [2] f3 27 [2] d8 0b [2] f6 29 [2] e2 32 [2] ed 28 [2] f3 35 [2] f1 34 [2] ea 32 [2] f6 35 [2] ea 1a }

  condition:
    any of them
}