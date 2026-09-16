rule TTP_XOR_MULT_DOSStub_23d4 {
  strings:
    $key_23d4 = { 77 bc [2] 03 a4 [2] 44 a6 [2] 03 b7 [2] 4d bb [2] 41 b1 [2] 56 ba [2] 4d f4 [2] 70 }

  condition:
    any of them
}