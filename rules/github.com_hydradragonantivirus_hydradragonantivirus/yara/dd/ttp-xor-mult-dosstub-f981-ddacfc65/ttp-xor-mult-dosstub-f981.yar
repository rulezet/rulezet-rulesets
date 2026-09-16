rule TTP_XOR_MULT_DOSStub_f981 {
  strings:
    $key_f981 = { ad e9 [2] d9 f1 [2] 9e f3 [2] d9 e2 [2] 97 ee [2] 9b e4 [2] 8c ef [2] 97 a1 [2] aa }

  condition:
    any of them
}