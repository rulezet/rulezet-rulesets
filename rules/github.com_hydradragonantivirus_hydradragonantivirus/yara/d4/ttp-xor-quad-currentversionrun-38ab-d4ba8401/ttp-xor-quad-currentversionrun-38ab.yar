rule TTP_XOR_QUAD_CurrentVersionRun_38ab {
  strings:
    $key_38ab = { 6b c4 [2] 4f ca [2] 64 e6 [2] 4a c4 [2] 5e df [2] 51 c5 [2] 4f d8 [2] 4d d9 [2] 56 df [2] 4a d8 [2] 56 f7 }

  condition:
    any of them
}