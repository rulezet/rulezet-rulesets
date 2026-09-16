rule TTP_XOR_QUAD_CurrentVersionRun_8344 {
  strings:
    $key_8344 = { d0 2b [2] f4 25 [2] df 09 [2] f1 2b [2] e5 30 [2] ea 2a [2] f4 37 [2] f6 36 [2] ed 30 [2] f1 37 [2] ed 18 }

  condition:
    any of them
}