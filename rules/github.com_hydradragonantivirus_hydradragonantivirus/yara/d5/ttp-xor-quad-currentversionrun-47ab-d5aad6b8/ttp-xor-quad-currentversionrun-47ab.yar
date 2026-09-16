rule TTP_XOR_QUAD_CurrentVersionRun_47ab {
  strings:
    $key_47ab = { 14 c4 [2] 30 ca [2] 1b e6 [2] 35 c4 [2] 21 df [2] 2e c5 [2] 30 d8 [2] 32 d9 [2] 29 df [2] 35 d8 [2] 29 f7 }

  condition:
    any of them
}