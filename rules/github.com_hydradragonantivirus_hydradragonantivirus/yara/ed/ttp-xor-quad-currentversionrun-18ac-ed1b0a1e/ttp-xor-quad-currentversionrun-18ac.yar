rule TTP_XOR_QUAD_CurrentVersionRun_18ac {
  strings:
    $key_18ac = { 4b c3 [2] 6f cd [2] 44 e1 [2] 6a c3 [2] 7e d8 [2] 71 c2 [2] 6f df [2] 6d de [2] 76 d8 [2] 6a df [2] 76 f0 }

  condition:
    any of them
}