rule TTP_XOR_QUAD_CurrentVersionRun_2fab {
  strings:
    $key_2fab = { 7c c4 [2] 58 ca [2] 73 e6 [2] 5d c4 [2] 49 df [2] 46 c5 [2] 58 d8 [2] 5a d9 [2] 41 df [2] 5d d8 [2] 41 f7 }

  condition:
    any of them
}