rule TTP_XOR_QUAD_CurrentVersionRun_3985 {
  strings:
    $key_3985 = { 6a ea [2] 4e e4 [2] 65 c8 [2] 4b ea [2] 5f f1 [2] 50 eb [2] 4e f6 [2] 4c f7 [2] 57 f1 [2] 4b f6 [2] 57 d9 }

  condition:
    any of them
}