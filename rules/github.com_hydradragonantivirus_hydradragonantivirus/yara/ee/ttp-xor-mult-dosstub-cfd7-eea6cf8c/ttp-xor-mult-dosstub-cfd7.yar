rule TTP_XOR_MULT_DOSStub_cfd7 {
  strings:
    $key_cfd7 = { 9b bf [2] ef a7 [2] a8 a5 [2] ef b4 [2] a1 b8 [2] ad b2 [2] ba b9 [2] a1 f7 [2] 9c }

  condition:
    any of them
}