rule TTP_XOR_QUAD_CurrentVersionRun_8ac5 {
  strings:
    $key_8ac5 = { d9 aa [2] fd a4 [2] d6 88 [2] f8 aa [2] ec b1 [2] e3 ab [2] fd b6 [2] ff b7 [2] e4 b1 [2] f8 b6 [2] e4 99 }

  condition:
    any of them
}