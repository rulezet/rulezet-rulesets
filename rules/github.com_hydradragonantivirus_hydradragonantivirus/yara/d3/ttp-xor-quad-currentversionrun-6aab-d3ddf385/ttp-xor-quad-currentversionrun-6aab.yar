rule TTP_XOR_QUAD_CurrentVersionRun_6aab {
  strings:
    $key_6aab = { 39 c4 [2] 1d ca [2] 36 e6 [2] 18 c4 [2] 0c df [2] 03 c5 [2] 1d d8 [2] 1f d9 [2] 04 df [2] 18 d8 [2] 04 f7 }

  condition:
    any of them
}