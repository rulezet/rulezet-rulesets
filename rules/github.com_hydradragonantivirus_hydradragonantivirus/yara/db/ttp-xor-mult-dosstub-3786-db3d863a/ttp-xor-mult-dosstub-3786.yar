rule TTP_XOR_MULT_DOSStub_3786 {
  strings:
    $key_3786 = { 63 ee [2] 17 f6 [2] 50 f4 [2] 17 e5 [2] 59 e9 [2] 55 e3 [2] 42 e8 [2] 59 a6 [2] 64 }

  condition:
    any of them
}