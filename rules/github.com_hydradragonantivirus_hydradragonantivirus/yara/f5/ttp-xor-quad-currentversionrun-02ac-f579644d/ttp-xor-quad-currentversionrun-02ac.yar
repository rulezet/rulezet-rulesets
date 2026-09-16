rule TTP_XOR_QUAD_CurrentVersionRun_02ac {
  strings:
    $key_02ac = { 51 c3 [2] 75 cd [2] 5e e1 [2] 70 c3 [2] 64 d8 [2] 6b c2 [2] 75 df [2] 77 de [2] 6c d8 [2] 70 df [2] 6c f0 }

  condition:
    any of them
}