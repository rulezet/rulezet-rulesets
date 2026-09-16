rule TTP_XOR_MULT_DOSStub_4597 {
  strings:
    $key_4597 = { 11 ff [2] 65 e7 [2] 22 e5 [2] 65 f4 [2] 2b f8 [2] 27 f2 [2] 30 f9 [2] 2b b7 [2] 16 }

  condition:
    any of them
}