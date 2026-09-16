rule TTP_XOR_QUAD_CurrentVersionRun_3cab {
  strings:
    $key_3cab = { 6f c4 [2] 4b ca [2] 60 e6 [2] 4e c4 [2] 5a df [2] 55 c5 [2] 4b d8 [2] 49 d9 [2] 52 df [2] 4e d8 [2] 52 f7 }

  condition:
    any of them
}