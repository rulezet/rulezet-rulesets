rule TTP_XOR_QUAD_CurrentVersionRun_18ab {
  strings:
    $key_18ab = { 4b c4 [2] 6f ca [2] 44 e6 [2] 6a c4 [2] 7e df [2] 71 c5 [2] 6f d8 [2] 6d d9 [2] 76 df [2] 6a d8 [2] 76 f7 }

  condition:
    any of them
}