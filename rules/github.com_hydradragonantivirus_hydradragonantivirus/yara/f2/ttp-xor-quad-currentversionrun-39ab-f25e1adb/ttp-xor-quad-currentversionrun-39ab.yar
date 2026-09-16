rule TTP_XOR_QUAD_CurrentVersionRun_39ab {
  strings:
    $key_39ab = { 6a c4 [2] 4e ca [2] 65 e6 [2] 4b c4 [2] 5f df [2] 50 c5 [2] 4e d8 [2] 4c d9 [2] 57 df [2] 4b d8 [2] 57 f7 }

  condition:
    any of them
}