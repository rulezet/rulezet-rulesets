rule TTP_XOR_QUAD_CurrentVersionRun_8a98 {
  strings:
    $key_8a98 = { d9 f7 [2] fd f9 [2] d6 d5 [2] f8 f7 [2] ec ec [2] e3 f6 [2] fd eb [2] ff ea [2] e4 ec [2] f8 eb [2] e4 c4 }

  condition:
    any of them
}