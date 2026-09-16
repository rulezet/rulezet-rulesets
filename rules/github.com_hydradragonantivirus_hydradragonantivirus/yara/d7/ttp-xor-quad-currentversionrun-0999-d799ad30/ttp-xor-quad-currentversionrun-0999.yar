rule TTP_XOR_QUAD_CurrentVersionRun_0999 {
  strings:
    $key_0999 = { 5a f6 [2] 7e f8 [2] 55 d4 [2] 7b f6 [2] 6f ed [2] 60 f7 [2] 7e ea [2] 7c eb [2] 67 ed [2] 7b ea [2] 67 c5 }

  condition:
    any of them
}