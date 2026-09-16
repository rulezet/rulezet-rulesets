rule TTP_XOR_MULT_DOSStub_52d4 {
  strings:
    $key_52d4 = { 06 bc [2] 72 a4 [2] 35 a6 [2] 72 b7 [2] 3c bb [2] 30 b1 [2] 27 ba [2] 3c f4 [2] 01 }

  condition:
    any of them
}