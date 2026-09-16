rule TTP_XOR_QUAD_CurrentVersionRun_e9ac {
  strings:
    $key_e9ac = { ba c3 [2] 9e cd [2] b5 e1 [2] 9b c3 [2] 8f d8 [2] 80 c2 [2] 9e df [2] 9c de [2] 87 d8 [2] 9b df [2] 87 f0 }

  condition:
    any of them
}