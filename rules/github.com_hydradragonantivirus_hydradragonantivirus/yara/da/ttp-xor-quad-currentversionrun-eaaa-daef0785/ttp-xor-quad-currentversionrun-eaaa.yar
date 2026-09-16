rule TTP_XOR_QUAD_CurrentVersionRun_eaaa {
  strings:
    $key_eaaa = { b9 c5 [2] 9d cb [2] b6 e7 [2] 98 c5 [2] 8c de [2] 83 c4 [2] 9d d9 [2] 9f d8 [2] 84 de [2] 98 d9 [2] 84 f6 }

  condition:
    any of them
}