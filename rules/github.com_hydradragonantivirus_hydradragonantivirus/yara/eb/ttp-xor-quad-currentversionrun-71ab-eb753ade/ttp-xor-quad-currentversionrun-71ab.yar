rule TTP_XOR_QUAD_CurrentVersionRun_71ab {
  strings:
    $key_71ab = { 22 c4 [2] 06 ca [2] 2d e6 [2] 03 c4 [2] 17 df [2] 18 c5 [2] 06 d8 [2] 04 d9 [2] 1f df [2] 03 d8 [2] 1f f7 }

  condition:
    any of them
}