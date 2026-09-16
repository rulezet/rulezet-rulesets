rule TTP_XOR_QUAD_CurrentVersionRun_1284 {
  strings:
    $key_1284 = { 41 eb [2] 65 e5 [2] 4e c9 [2] 60 eb [2] 74 f0 [2] 7b ea [2] 65 f7 [2] 67 f6 [2] 7c f0 [2] 60 f7 [2] 7c d8 }

  condition:
    any of them
}