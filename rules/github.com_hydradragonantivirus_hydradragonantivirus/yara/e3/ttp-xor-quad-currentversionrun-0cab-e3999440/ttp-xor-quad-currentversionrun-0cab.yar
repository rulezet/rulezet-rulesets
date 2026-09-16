rule TTP_XOR_QUAD_CurrentVersionRun_0cab {
  strings:
    $key_0cab = { 5f c4 [2] 7b ca [2] 50 e6 [2] 7e c4 [2] 6a df [2] 65 c5 [2] 7b d8 [2] 79 d9 [2] 62 df [2] 7e d8 [2] 62 f7 }

  condition:
    any of them
}