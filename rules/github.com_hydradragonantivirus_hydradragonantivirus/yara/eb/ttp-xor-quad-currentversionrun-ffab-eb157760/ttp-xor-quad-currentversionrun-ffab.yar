rule TTP_XOR_QUAD_CurrentVersionRun_ffab {
  strings:
    $key_ffab = { ac c4 [2] 88 ca [2] a3 e6 [2] 8d c4 [2] 99 df [2] 96 c5 [2] 88 d8 [2] 8a d9 [2] 91 df [2] 8d d8 [2] 91 f7 }

  condition:
    any of them
}