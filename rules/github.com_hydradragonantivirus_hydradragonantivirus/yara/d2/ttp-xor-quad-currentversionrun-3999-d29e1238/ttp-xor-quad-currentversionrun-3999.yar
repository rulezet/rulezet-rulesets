rule TTP_XOR_QUAD_CurrentVersionRun_3999 {
  strings:
    $key_3999 = { 6a f6 [2] 4e f8 [2] 65 d4 [2] 4b f6 [2] 5f ed [2] 50 f7 [2] 4e ea [2] 4c eb [2] 57 ed [2] 4b ea [2] 57 c5 }

  condition:
    any of them
}