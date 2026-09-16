rule TTP_XOR_QUAD_CurrentVersionRun_84f5 {
  strings:
    $key_84f5 = { d7 9a [2] f3 94 [2] d8 b8 [2] f6 9a [2] e2 81 [2] ed 9b [2] f3 86 [2] f1 87 [2] ea 81 [2] f6 86 [2] ea a9 }

  condition:
    any of them
}