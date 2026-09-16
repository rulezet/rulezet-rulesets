rule TTP_XOR_QUAD_CurrentVersionRun_3a9c {
  strings:
    $key_3a9c = { 69 f3 [2] 4d fd [2] 66 d1 [2] 48 f3 [2] 5c e8 [2] 53 f2 [2] 4d ef [2] 4f ee [2] 54 e8 [2] 48 ef [2] 54 c0 }

  condition:
    any of them
}