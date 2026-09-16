rule TTP_XOR_MULT_DOSStub_f199 {
  strings:
    $key_f199 = { a5 f1 [2] d1 e9 [2] 96 eb [2] d1 fa [2] 9f f6 [2] 93 fc [2] 84 f7 [2] 9f b9 [2] a2 }

  condition:
    any of them
}