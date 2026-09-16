rule TTP_XOR_QUAD_CurrentVersionRun_f4ac {
  strings:
    $key_f4ac = { a7 c3 [2] 83 cd [2] a8 e1 [2] 86 c3 [2] 92 d8 [2] 9d c2 [2] 83 df [2] 81 de [2] 9a d8 [2] 86 df [2] 9a f0 }

  condition:
    any of them
}