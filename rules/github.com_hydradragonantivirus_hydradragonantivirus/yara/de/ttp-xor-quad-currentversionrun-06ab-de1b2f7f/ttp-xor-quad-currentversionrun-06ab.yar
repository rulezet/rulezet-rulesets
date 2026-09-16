rule TTP_XOR_QUAD_CurrentVersionRun_06ab {
  strings:
    $key_06ab = { 55 c4 [2] 71 ca [2] 5a e6 [2] 74 c4 [2] 60 df [2] 6f c5 [2] 71 d8 [2] 73 d9 [2] 68 df [2] 74 d8 [2] 68 f7 }

  condition:
    any of them
}