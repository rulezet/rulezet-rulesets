rule TTP_XOR_QUAD_CurrentVersionRun_8aaa {
  strings:
    $key_8aaa = { d9 c5 [2] fd cb [2] d6 e7 [2] f8 c5 [2] ec de [2] e3 c4 [2] fd d9 [2] ff d8 [2] e4 de [2] f8 d9 [2] e4 f6 }

  condition:
    any of them
}