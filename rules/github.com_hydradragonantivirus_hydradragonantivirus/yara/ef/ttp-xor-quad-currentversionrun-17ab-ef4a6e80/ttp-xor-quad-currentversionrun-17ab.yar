rule TTP_XOR_QUAD_CurrentVersionRun_17ab {
  strings:
    $key_17ab = { 44 c4 [2] 60 ca [2] 4b e6 [2] 65 c4 [2] 71 df [2] 7e c5 [2] 60 d8 [2] 62 d9 [2] 79 df [2] 65 d8 [2] 79 f7 }

  condition:
    any of them
}