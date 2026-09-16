rule TTP_XOR_QUAD_CurrentVersionRun_e3ab {
  strings:
    $key_e3ab = { b0 c4 [2] 94 ca [2] bf e6 [2] 91 c4 [2] 85 df [2] 8a c5 [2] 94 d8 [2] 96 d9 [2] 8d df [2] 91 d8 [2] 8d f7 }

  condition:
    any of them
}