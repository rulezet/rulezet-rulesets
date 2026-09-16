rule TTP_XOR_QUAD_CurrentVersionRun_1c85 {
  strings:
    $key_1c85 = { 4f ea [2] 6b e4 [2] 40 c8 [2] 6e ea [2] 7a f1 [2] 75 eb [2] 6b f6 [2] 69 f7 [2] 72 f1 [2] 6e f6 [2] 72 d9 }

  condition:
    any of them
}