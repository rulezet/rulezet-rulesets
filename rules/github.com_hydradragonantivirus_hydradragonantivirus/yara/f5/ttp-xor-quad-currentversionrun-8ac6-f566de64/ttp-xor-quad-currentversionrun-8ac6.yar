rule TTP_XOR_QUAD_CurrentVersionRun_8ac6 {
  strings:
    $key_8ac6 = { d9 a9 [2] fd a7 [2] d6 8b [2] f8 a9 [2] ec b2 [2] e3 a8 [2] fd b5 [2] ff b4 [2] e4 b2 [2] f8 b5 [2] e4 9a }

  condition:
    any of them
}