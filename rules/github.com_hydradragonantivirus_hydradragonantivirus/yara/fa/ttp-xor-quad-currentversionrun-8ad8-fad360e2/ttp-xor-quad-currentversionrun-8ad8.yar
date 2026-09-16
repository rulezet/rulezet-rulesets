rule TTP_XOR_QUAD_CurrentVersionRun_8ad8 {
  strings:
    $key_8ad8 = { d9 b7 [2] fd b9 [2] d6 95 [2] f8 b7 [2] ec ac [2] e3 b6 [2] fd ab [2] ff aa [2] e4 ac [2] f8 ab [2] e4 84 }

  condition:
    any of them
}