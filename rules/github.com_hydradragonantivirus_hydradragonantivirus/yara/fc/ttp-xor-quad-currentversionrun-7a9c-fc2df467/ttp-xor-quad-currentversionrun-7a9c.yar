rule TTP_XOR_QUAD_CurrentVersionRun_7a9c {
  strings:
    $key_7a9c = { 29 f3 [2] 0d fd [2] 26 d1 [2] 08 f3 [2] 1c e8 [2] 13 f2 [2] 0d ef [2] 0f ee [2] 14 e8 [2] 08 ef [2] 14 c0 }

  condition:
    any of them
}