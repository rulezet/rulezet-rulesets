rule TTP_XOR_QUAD_CurrentVersionRun_8448 {
  strings:
    $key_8448 = { d7 27 [2] f3 29 [2] d8 05 [2] f6 27 [2] e2 3c [2] ed 26 [2] f3 3b [2] f1 3a [2] ea 3c [2] f6 3b [2] ea 14 }

  condition:
    any of them
}