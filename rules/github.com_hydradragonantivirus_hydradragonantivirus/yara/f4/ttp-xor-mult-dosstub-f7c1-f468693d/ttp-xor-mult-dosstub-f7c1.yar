rule TTP_XOR_MULT_DOSStub_f7c1 {
  strings:
    $key_f7c1 = { a3 a9 [2] d7 b1 [2] 90 b3 [2] d7 a2 [2] 99 ae [2] 95 a4 [2] 82 af [2] 99 e1 [2] a4 }

  condition:
    any of them
}