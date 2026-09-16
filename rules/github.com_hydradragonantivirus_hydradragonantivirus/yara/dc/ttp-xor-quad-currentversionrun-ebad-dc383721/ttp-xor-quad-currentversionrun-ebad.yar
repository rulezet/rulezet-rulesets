rule TTP_XOR_QUAD_CurrentVersionRun_ebad {
  strings:
    $key_ebad = { b8 c2 [2] 9c cc [2] b7 e0 [2] 99 c2 [2] 8d d9 [2] 82 c3 [2] 9c de [2] 9e df [2] 85 d9 [2] 99 de [2] 85 f1 }

  condition:
    any of them
}