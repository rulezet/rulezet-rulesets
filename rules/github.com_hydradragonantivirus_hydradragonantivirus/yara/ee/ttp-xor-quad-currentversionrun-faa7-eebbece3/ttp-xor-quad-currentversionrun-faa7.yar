rule TTP_XOR_QUAD_CurrentVersionRun_faa7 {
  strings:
    $key_faa7 = { a9 c8 [2] 8d c6 [2] a6 ea [2] 88 c8 [2] 9c d3 [2] 93 c9 [2] 8d d4 [2] 8f d5 [2] 94 d3 [2] 88 d4 [2] 94 fb }

  condition:
    any of them
}