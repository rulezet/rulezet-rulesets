rule TTP_XOR_MULT_DOSStub_cfc8 {
  strings:
    $key_cfc8 = { 9b a0 [2] ef b8 [2] a8 ba [2] ef ab [2] a1 a7 [2] ad ad [2] ba a6 [2] a1 e8 [2] 9c }

  condition:
    any of them
}