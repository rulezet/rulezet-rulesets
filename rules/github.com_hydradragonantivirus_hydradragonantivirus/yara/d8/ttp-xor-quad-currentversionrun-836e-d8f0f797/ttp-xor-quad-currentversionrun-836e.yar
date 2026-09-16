rule TTP_XOR_QUAD_CurrentVersionRun_836e {
  strings:
    $key_836e = { d0 01 [2] f4 0f [2] df 23 [2] f1 01 [2] e5 1a [2] ea 00 [2] f4 1d [2] f6 1c [2] ed 1a [2] f1 1d [2] ed 32 }

  condition:
    any of them
}