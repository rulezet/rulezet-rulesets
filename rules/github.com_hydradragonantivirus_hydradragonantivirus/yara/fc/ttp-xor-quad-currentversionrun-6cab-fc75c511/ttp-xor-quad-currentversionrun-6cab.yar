rule TTP_XOR_QUAD_CurrentVersionRun_6cab {
  strings:
    $key_6cab = { 3f c4 [2] 1b ca [2] 30 e6 [2] 1e c4 [2] 0a df [2] 05 c5 [2] 1b d8 [2] 19 d9 [2] 02 df [2] 1e d8 [2] 02 f7 }

  condition:
    any of them
}