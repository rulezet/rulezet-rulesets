rule TTP_XOR_QUAD_CurrentVersionRun_8427 {
  strings:
    $key_8427 = { d7 48 [2] f3 46 [2] d8 6a [2] f6 48 [2] e2 53 [2] ed 49 [2] f3 54 [2] f1 55 [2] ea 53 [2] f6 54 [2] ea 7b }

  condition:
    any of them
}