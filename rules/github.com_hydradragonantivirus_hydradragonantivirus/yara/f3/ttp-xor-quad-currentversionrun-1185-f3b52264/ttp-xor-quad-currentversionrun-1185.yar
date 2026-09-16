rule TTP_XOR_QUAD_CurrentVersionRun_1185 {
  strings:
    $key_1185 = { 42 ea [2] 66 e4 [2] 4d c8 [2] 63 ea [2] 77 f1 [2] 78 eb [2] 66 f6 [2] 64 f7 [2] 7f f1 [2] 63 f6 [2] 7f d9 }

  condition:
    any of them
}