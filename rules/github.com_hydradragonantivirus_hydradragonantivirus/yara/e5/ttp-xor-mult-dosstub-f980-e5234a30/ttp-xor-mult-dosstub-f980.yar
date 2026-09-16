rule TTP_XOR_MULT_DOSStub_f980 {
  strings:
    $key_f980 = { ad e8 [2] d9 f0 [2] 9e f2 [2] d9 e3 [2] 97 ef [2] 9b e5 [2] 8c ee [2] 97 a0 [2] aa }

  condition:
    any of them
}