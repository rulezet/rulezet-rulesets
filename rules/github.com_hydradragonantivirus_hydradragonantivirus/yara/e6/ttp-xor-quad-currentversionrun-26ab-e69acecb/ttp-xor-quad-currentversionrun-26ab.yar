rule TTP_XOR_QUAD_CurrentVersionRun_26ab {
  strings:
    $key_26ab = { 75 c4 [2] 51 ca [2] 7a e6 [2] 54 c4 [2] 40 df [2] 4f c5 [2] 51 d8 [2] 53 d9 [2] 48 df [2] 54 d8 [2] 48 f7 }

  condition:
    any of them
}