rule TTP_XOR_QUAD_CurrentVersionRun_faa6 {
  strings:
    $key_faa6 = { a9 c9 [2] 8d c7 [2] a6 eb [2] 88 c9 [2] 9c d2 [2] 93 c8 [2] 8d d5 [2] 8f d4 [2] 94 d2 [2] 88 d5 [2] 94 fa }

  condition:
    any of them
}