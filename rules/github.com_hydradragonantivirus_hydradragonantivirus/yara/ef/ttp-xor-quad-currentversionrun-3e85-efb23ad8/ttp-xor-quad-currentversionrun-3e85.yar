rule TTP_XOR_QUAD_CurrentVersionRun_3e85 {
  strings:
    $key_3e85 = { 6d ea [2] 49 e4 [2] 62 c8 [2] 4c ea [2] 58 f1 [2] 57 eb [2] 49 f6 [2] 4b f7 [2] 50 f1 [2] 4c f6 [2] 50 d9 }

  condition:
    any of them
}