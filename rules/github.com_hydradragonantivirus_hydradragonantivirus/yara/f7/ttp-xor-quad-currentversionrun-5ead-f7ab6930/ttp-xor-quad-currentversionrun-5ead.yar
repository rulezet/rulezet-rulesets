rule TTP_XOR_QUAD_CurrentVersionRun_5ead {
  strings:
    $key_5ead = { 0d c2 [2] 29 cc [2] 02 e0 [2] 2c c2 [2] 38 d9 [2] 37 c3 [2] 29 de [2] 2b df [2] 30 d9 [2] 2c de [2] 30 f1 }

  condition:
    any of them
}