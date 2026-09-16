rule TTP_XOR_QUAD_CurrentVersionRun_31ac {
  strings:
    $key_31ac = { 62 c3 [2] 46 cd [2] 6d e1 [2] 43 c3 [2] 57 d8 [2] 58 c2 [2] 46 df [2] 44 de [2] 5f d8 [2] 43 df [2] 5f f0 }

  condition:
    any of them
}