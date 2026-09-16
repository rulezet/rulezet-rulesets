rule TTP_XOR_QUAD_CurrentVersionRun_8454 {
  strings:
    $key_8454 = { d7 3b [2] f3 35 [2] d8 19 [2] f6 3b [2] e2 20 [2] ed 3a [2] f3 27 [2] f1 26 [2] ea 20 [2] f6 27 [2] ea 08 }

  condition:
    any of them
}