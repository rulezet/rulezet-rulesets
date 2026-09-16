rule TTP_XOR_MULT_DOSStub_4ab5 {
  strings:
    $key_4ab5 = { 1e dd [2] 6a c5 [2] 2d c7 [2] 6a d6 [2] 24 da [2] 28 d0 [2] 3f db [2] 24 95 [2] 19 }

  condition:
    any of them
}