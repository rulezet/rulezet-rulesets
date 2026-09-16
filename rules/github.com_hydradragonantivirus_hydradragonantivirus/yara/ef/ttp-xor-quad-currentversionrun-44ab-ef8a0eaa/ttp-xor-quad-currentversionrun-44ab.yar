rule TTP_XOR_QUAD_CurrentVersionRun_44ab {
  strings:
    $key_44ab = { 17 c4 [2] 33 ca [2] 18 e6 [2] 36 c4 [2] 22 df [2] 2d c5 [2] 33 d8 [2] 31 d9 [2] 2a df [2] 36 d8 [2] 2a f7 }

  condition:
    any of them
}