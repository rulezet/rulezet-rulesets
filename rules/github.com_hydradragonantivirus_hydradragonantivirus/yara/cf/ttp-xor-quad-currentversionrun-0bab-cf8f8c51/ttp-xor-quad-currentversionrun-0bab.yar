rule TTP_XOR_QUAD_CurrentVersionRun_0bab {
  strings:
    $key_0bab = { 58 c4 [2] 7c ca [2] 57 e6 [2] 79 c4 [2] 6d df [2] 62 c5 [2] 7c d8 [2] 7e d9 [2] 65 df [2] 79 d8 [2] 65 f7 }

  condition:
    any of them
}