rule TTP_XOR_QUAD_CurrentVersionRun_31ab {
  strings:
    $key_31ab = { 62 c4 [2] 46 ca [2] 6d e6 [2] 43 c4 [2] 57 df [2] 58 c5 [2] 46 d8 [2] 44 d9 [2] 5f df [2] 43 d8 [2] 5f f7 }

  condition:
    any of them
}