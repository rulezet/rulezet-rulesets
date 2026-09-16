rule TTP_XOR_QUAD_CurrentVersionRun_64ac {
  strings:
    $key_64ac = { 37 c3 [2] 13 cd [2] 38 e1 [2] 16 c3 [2] 02 d8 [2] 0d c2 [2] 13 df [2] 11 de [2] 0a d8 [2] 16 df [2] 0a f0 }

  condition:
    any of them
}