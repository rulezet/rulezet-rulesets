rule TTP_XOR_QUAD_CurrentVersionRun_21ab {
  strings:
    $key_21ab = { 72 c4 [2] 56 ca [2] 7d e6 [2] 53 c4 [2] 47 df [2] 48 c5 [2] 56 d8 [2] 54 d9 [2] 4f df [2] 53 d8 [2] 4f f7 }

  condition:
    any of them
}