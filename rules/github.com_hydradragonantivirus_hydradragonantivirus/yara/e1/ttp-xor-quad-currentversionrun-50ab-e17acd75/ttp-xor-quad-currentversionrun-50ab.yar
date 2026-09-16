rule TTP_XOR_QUAD_CurrentVersionRun_50ab {
  strings:
    $key_50ab = { 03 c4 [2] 27 ca [2] 0c e6 [2] 22 c4 [2] 36 df [2] 39 c5 [2] 27 d8 [2] 25 d9 [2] 3e df [2] 22 d8 [2] 3e f7 }

  condition:
    any of them
}