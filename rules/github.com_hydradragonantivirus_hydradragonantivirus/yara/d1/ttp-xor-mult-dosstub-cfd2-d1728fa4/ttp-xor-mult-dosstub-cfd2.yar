rule TTP_XOR_MULT_DOSStub_cfd2 {
  strings:
    $key_cfd2 = { 9b ba [2] ef a2 [2] a8 a0 [2] ef b1 [2] a1 bd [2] ad b7 [2] ba bc [2] a1 f2 [2] 9c }

  condition:
    any of them
}