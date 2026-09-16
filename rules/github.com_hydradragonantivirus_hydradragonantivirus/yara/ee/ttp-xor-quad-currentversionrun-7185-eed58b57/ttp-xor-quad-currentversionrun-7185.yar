rule TTP_XOR_QUAD_CurrentVersionRun_7185 {
  strings:
    $key_7185 = { 22 ea [2] 06 e4 [2] 2d c8 [2] 03 ea [2] 17 f1 [2] 18 eb [2] 06 f6 [2] 04 f7 [2] 1f f1 [2] 03 f6 [2] 1f d9 }

  condition:
    any of them
}