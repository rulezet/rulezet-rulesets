rule TTP_XOR_QUAD_CurrentVersionRun_28ac {
  strings:
    $key_28ac = { 7b c3 [2] 5f cd [2] 74 e1 [2] 5a c3 [2] 4e d8 [2] 41 c2 [2] 5f df [2] 5d de [2] 46 d8 [2] 5a df [2] 46 f0 }

  condition:
    any of them
}