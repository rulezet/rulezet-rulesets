rule TTP_XOR_QUAD_CurrentVersionRun_3aaa {
  strings:
    $key_3aaa = { 69 c5 [2] 4d cb [2] 66 e7 [2] 48 c5 [2] 5c de [2] 53 c4 [2] 4d d9 [2] 4f d8 [2] 54 de [2] 48 d9 [2] 54 f6 }

  condition:
    any of them
}