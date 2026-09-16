rule TTP_XOR_QUAD_CurrentVersionRun_42b1 {
  strings:
    $key_42b1 = { 11 de [2] 35 d0 [2] 1e fc [2] 30 de [2] 24 c5 [2] 2b df [2] 35 c2 [2] 37 c3 [2] 2c c5 [2] 30 c2 [2] 2c ed }

  condition:
    any of them
}