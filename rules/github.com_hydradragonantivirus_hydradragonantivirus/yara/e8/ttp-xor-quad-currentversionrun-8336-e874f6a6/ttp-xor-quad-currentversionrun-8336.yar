rule TTP_XOR_QUAD_CurrentVersionRun_8336 {
  strings:
    $key_8336 = { d0 59 [2] f4 57 [2] df 7b [2] f1 59 [2] e5 42 [2] ea 58 [2] f4 45 [2] f6 44 [2] ed 42 [2] f1 45 [2] ed 6a }

  condition:
    any of them
}