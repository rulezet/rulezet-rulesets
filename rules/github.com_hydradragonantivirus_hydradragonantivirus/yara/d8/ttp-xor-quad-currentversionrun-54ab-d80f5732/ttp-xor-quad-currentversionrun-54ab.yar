rule TTP_XOR_QUAD_CurrentVersionRun_54ab {
  strings:
    $key_54ab = { 07 c4 [2] 23 ca [2] 08 e6 [2] 26 c4 [2] 32 df [2] 3d c5 [2] 23 d8 [2] 21 d9 [2] 3a df [2] 26 d8 [2] 3a f7 }

  condition:
    any of them
}