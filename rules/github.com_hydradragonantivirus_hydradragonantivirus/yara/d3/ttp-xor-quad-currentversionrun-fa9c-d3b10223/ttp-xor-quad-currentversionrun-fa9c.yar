rule TTP_XOR_QUAD_CurrentVersionRun_fa9c {
  strings:
    $key_fa9c = { a9 f3 [2] 8d fd [2] a6 d1 [2] 88 f3 [2] 9c e8 [2] 93 f2 [2] 8d ef [2] 8f ee [2] 94 e8 [2] 88 ef [2] 94 c0 }

  condition:
    any of them
}