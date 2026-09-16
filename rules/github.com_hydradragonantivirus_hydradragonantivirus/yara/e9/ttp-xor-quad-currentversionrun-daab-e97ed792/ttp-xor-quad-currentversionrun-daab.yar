rule TTP_XOR_QUAD_CurrentVersionRun_daab {
  strings:
    $key_daab = { 89 c4 [2] ad ca [2] 86 e6 [2] a8 c4 [2] bc df [2] b3 c5 [2] ad d8 [2] af d9 [2] b4 df [2] a8 d8 [2] b4 f7 }

  condition:
    any of them
}