rule TTP_XOR_QUAD_CurrentVersionRun_8458 {
  strings:
    $key_8458 = { d7 37 [2] f3 39 [2] d8 15 [2] f6 37 [2] e2 2c [2] ed 36 [2] f3 2b [2] f1 2a [2] ea 2c [2] f6 2b [2] ea 04 }

  condition:
    any of them
}