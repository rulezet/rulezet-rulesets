rule TTP_XOR_MULT_DOSStub_10d4 {
  strings:
    $key_10d4 = { 44 bc [2] 30 a4 [2] 77 a6 [2] 30 b7 [2] 7e bb [2] 72 b1 [2] 65 ba [2] 7e f4 [2] 43 }

  condition:
    any of them
}