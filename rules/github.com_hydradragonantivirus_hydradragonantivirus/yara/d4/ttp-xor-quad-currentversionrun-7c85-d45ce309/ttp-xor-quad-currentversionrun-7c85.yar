rule TTP_XOR_QUAD_CurrentVersionRun_7c85 {
  strings:
    $key_7c85 = { 2f ea [2] 0b e4 [2] 20 c8 [2] 0e ea [2] 1a f1 [2] 15 eb [2] 0b f6 [2] 09 f7 [2] 12 f1 [2] 0e f6 [2] 12 d9 }

  condition:
    any of them
}