rule TTP_XOR_QUAD_CurrentVersionRun_2185 {
  strings:
    $key_2185 = { 72 ea [2] 56 e4 [2] 7d c8 [2] 53 ea [2] 47 f1 [2] 48 eb [2] 56 f6 [2] 54 f7 [2] 4f f1 [2] 53 f6 [2] 4f d9 }

  condition:
    any of them
}