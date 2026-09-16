rule TTP_XOR_QUAD_CurrentVersionRun_8316 {
  strings:
    $key_8316 = { d0 79 [2] f4 77 [2] df 5b [2] f1 79 [2] e5 62 [2] ea 78 [2] f4 65 [2] f6 64 [2] ed 62 [2] f1 65 [2] ed 4a }

  condition:
    any of them
}