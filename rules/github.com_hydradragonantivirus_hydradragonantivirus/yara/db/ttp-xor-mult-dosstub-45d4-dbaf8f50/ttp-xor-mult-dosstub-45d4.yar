rule TTP_XOR_MULT_DOSStub_45d4 {
  strings:
    $key_45d4 = { 11 bc [2] 65 a4 [2] 22 a6 [2] 65 b7 [2] 2b bb [2] 27 b1 [2] 30 ba [2] 2b f4 [2] 16 }

  condition:
    any of them
}