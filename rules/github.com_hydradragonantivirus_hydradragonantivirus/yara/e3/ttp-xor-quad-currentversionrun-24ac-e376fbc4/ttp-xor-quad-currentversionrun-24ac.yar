rule TTP_XOR_QUAD_CurrentVersionRun_24ac {
  strings:
    $key_24ac = { 77 c3 [2] 53 cd [2] 78 e1 [2] 56 c3 [2] 42 d8 [2] 4d c2 [2] 53 df [2] 51 de [2] 4a d8 [2] 56 df [2] 4a f0 }

  condition:
    any of them
}