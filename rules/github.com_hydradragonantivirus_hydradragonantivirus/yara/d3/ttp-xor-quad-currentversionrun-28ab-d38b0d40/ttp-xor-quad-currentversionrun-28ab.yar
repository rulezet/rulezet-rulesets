rule TTP_XOR_QUAD_CurrentVersionRun_28ab {
  strings:
    $key_28ab = { 7b c4 [2] 5f ca [2] 74 e6 [2] 5a c4 [2] 4e df [2] 41 c5 [2] 5f d8 [2] 5d d9 [2] 46 df [2] 5a d8 [2] 46 f7 }

  condition:
    any of them
}