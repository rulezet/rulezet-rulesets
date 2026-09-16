rule TTP_XOR_QUAD_CurrentVersionRun_8354 {
  strings:
    $key_8354 = { d0 3b [2] f4 35 [2] df 19 [2] f1 3b [2] e5 20 [2] ea 3a [2] f4 27 [2] f6 26 [2] ed 20 [2] f1 27 [2] ed 08 }

  condition:
    any of them
}