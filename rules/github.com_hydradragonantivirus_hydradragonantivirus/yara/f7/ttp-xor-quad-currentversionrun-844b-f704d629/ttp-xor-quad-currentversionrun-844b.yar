rule TTP_XOR_QUAD_CurrentVersionRun_844b {
  strings:
    $key_844b = { d7 24 [2] f3 2a [2] d8 06 [2] f6 24 [2] e2 3f [2] ed 25 [2] f3 38 [2] f1 39 [2] ea 3f [2] f6 38 [2] ea 17 }

  condition:
    any of them
}