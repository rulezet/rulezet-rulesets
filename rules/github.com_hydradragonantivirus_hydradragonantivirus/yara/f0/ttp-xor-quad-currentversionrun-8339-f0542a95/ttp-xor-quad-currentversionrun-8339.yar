rule TTP_XOR_QUAD_CurrentVersionRun_8339 {
  strings:
    $key_8339 = { d0 56 [2] f4 58 [2] df 74 [2] f1 56 [2] e5 4d [2] ea 57 [2] f4 4a [2] f6 4b [2] ed 4d [2] f1 4a [2] ed 65 }

  condition:
    any of them
}