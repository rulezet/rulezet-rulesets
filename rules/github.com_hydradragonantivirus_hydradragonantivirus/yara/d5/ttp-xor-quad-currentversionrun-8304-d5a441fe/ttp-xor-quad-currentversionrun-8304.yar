rule TTP_XOR_QUAD_CurrentVersionRun_8304 {
  strings:
    $key_8304 = { d0 6b [2] f4 65 [2] df 49 [2] f1 6b [2] e5 70 [2] ea 6a [2] f4 77 [2] f6 76 [2] ed 70 [2] f1 77 [2] ed 58 }

  condition:
    any of them
}