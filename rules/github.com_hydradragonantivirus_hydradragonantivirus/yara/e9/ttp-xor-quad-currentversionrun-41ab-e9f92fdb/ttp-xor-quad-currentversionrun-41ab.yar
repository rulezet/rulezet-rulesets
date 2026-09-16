rule TTP_XOR_QUAD_CurrentVersionRun_41ab {
  strings:
    $key_41ab = { 12 c4 [2] 36 ca [2] 1d e6 [2] 33 c4 [2] 27 df [2] 28 c5 [2] 36 d8 [2] 34 d9 [2] 2f df [2] 33 d8 [2] 2f f7 }

  condition:
    any of them
}