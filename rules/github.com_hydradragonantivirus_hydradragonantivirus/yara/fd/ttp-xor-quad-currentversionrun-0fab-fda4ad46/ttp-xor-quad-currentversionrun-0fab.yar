rule TTP_XOR_QUAD_CurrentVersionRun_0fab {
  strings:
    $key_0fab = { 5c c4 [2] 78 ca [2] 53 e6 [2] 7d c4 [2] 69 df [2] 66 c5 [2] 78 d8 [2] 7a d9 [2] 61 df [2] 7d d8 [2] 61 f7 }

  condition:
    any of them
}