rule TTP_XOR_MULT_DOSStub_cfd6 {
  strings:
    $key_cfd6 = { 9b be [2] ef a6 [2] a8 a4 [2] ef b5 [2] a1 b9 [2] ad b3 [2] ba b8 [2] a1 f6 [2] 9c }

  condition:
    any of them
}