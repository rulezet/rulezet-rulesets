rule TTP_XOR_QUAD_CurrentVersionRun_fab5 {
  strings:
    $key_fab5 = { a9 da [2] 8d d4 [2] a6 f8 [2] 88 da [2] 9c c1 [2] 93 db [2] 8d c6 [2] 8f c7 [2] 94 c1 [2] 88 c6 [2] 94 e9 }

  condition:
    any of them
}