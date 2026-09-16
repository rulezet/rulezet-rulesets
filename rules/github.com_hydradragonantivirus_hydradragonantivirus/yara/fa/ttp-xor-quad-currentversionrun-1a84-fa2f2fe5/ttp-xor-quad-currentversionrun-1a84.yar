rule TTP_XOR_QUAD_CurrentVersionRun_1a84 {
  strings:
    $key_1a84 = { 49 eb [2] 6d e5 [2] 46 c9 [2] 68 eb [2] 7c f0 [2] 73 ea [2] 6d f7 [2] 6f f6 [2] 74 f0 [2] 68 f7 [2] 74 d8 }

  condition:
    any of them
}