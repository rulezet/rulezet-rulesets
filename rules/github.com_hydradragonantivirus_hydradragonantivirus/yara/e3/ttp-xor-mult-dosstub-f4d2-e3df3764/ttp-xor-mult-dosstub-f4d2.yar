rule TTP_XOR_MULT_DOSStub_f4d2 {
  strings:
    $key_f4d2 = { a0 ba [2] d4 a2 [2] 93 a0 [2] d4 b1 [2] 9a bd [2] 96 b7 [2] 81 bc [2] 9a f2 [2] a7 }

  condition:
    any of them
}