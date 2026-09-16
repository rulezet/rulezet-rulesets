rule TTP_XOR_MULT_DOSStub_72d4 {
  strings:
    $key_72d4 = { 26 bc [2] 52 a4 [2] 15 a6 [2] 52 b7 [2] 1c bb [2] 10 b1 [2] 07 ba [2] 1c f4 [2] 21 }

  condition:
    any of them
}