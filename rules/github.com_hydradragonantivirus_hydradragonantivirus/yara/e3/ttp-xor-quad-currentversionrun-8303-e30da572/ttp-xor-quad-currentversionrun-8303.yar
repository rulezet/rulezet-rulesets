rule TTP_XOR_QUAD_CurrentVersionRun_8303 {
  strings:
    $key_8303 = { d0 6c [2] f4 62 [2] df 4e [2] f1 6c [2] e5 77 [2] ea 6d [2] f4 70 [2] f6 71 [2] ed 77 [2] f1 70 [2] ed 5f }

  condition:
    any of them
}