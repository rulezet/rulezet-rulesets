rule TTP_XOR_QUAD_CurrentVersionRun_6985 {
  strings:
    $key_6985 = { 3a ea [2] 1e e4 [2] 35 c8 [2] 1b ea [2] 0f f1 [2] 00 eb [2] 1e f6 [2] 1c f7 [2] 07 f1 [2] 1b f6 [2] 07 d9 }

  condition:
    any of them
}