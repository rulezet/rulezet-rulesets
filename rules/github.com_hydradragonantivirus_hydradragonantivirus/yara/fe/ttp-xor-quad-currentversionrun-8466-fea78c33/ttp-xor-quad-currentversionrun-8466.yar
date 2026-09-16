rule TTP_XOR_QUAD_CurrentVersionRun_8466 {
  strings:
    $key_8466 = { d7 09 [2] f3 07 [2] d8 2b [2] f6 09 [2] e2 12 [2] ed 08 [2] f3 15 [2] f1 14 [2] ea 12 [2] f6 15 [2] ea 3a }

  condition:
    any of them
}