rule TTP_XOR_QUAD_CurrentVersionRun_e999 {
  strings:
    $key_e999 = { ba f6 [2] 9e f8 [2] b5 d4 [2] 9b f6 [2] 8f ed [2] 80 f7 [2] 9e ea [2] 9c eb [2] 87 ed [2] 9b ea [2] 87 c5 }

  condition:
    any of them
}