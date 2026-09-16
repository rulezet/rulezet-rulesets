rule TTP_XOR_QUAD_CurrentVersionRun_83e9 {
  strings:
    $key_83e9 = { d0 86 [2] f4 88 [2] df a4 [2] f1 86 [2] e5 9d [2] ea 87 [2] f4 9a [2] f6 9b [2] ed 9d [2] f1 9a [2] ed b5 }

  condition:
    any of them
}