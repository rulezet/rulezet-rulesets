rule TTP_XOR_QUAD_CurrentVersionRun_07ab {
  strings:
    $key_07ab = { 54 c4 [2] 70 ca [2] 5b e6 [2] 75 c4 [2] 61 df [2] 6e c5 [2] 70 d8 [2] 72 d9 [2] 69 df [2] 75 d8 [2] 69 f7 }

  condition:
    any of them
}