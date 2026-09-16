rule TTP_XOR_MULT_DOSStub_cfd9 {
  strings:
    $key_cfd9 = { 9b b1 [2] ef a9 [2] a8 ab [2] ef ba [2] a1 b6 [2] ad bc [2] ba b7 [2] a1 f9 [2] 9c }

  condition:
    any of them
}