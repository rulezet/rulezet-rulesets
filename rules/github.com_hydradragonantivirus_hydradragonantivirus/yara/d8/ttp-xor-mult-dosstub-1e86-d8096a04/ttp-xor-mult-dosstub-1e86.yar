rule TTP_XOR_MULT_DOSStub_1e86 {
  strings:
    $key_1e86 = { 4a ee [2] 3e f6 [2] 79 f4 [2] 3e e5 [2] 70 e9 [2] 7c e3 [2] 6b e8 [2] 70 a6 [2] 4d }

  condition:
    any of them
}