rule TTP_XOR_QUAD_CurrentVersionRun_0786 {
  strings:
    $key_0786 = { 54 e9 [2] 70 e7 [2] 5b cb [2] 75 e9 [2] 61 f2 [2] 6e e8 [2] 70 f5 [2] 72 f4 [2] 69 f2 [2] 75 f5 [2] 69 da }

  condition:
    any of them
}