rule TTP_XOR_QUAD_CurrentVersionRun_1aab {
  strings:
    $key_1aab = { 49 c4 [2] 6d ca [2] 46 e6 [2] 68 c4 [2] 7c df [2] 73 c5 [2] 6d d8 [2] 6f d9 [2] 74 df [2] 68 d8 [2] 74 f7 }

  condition:
    any of them
}