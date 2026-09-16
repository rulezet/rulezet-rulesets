rule TTP_XOR_MULT_DOSStub_f786 {
  strings:
    $key_f786 = { a3 ee [2] d7 f6 [2] 90 f4 [2] d7 e5 [2] 99 e9 [2] 95 e3 [2] 82 e8 [2] 99 a6 [2] a4 }

  condition:
    any of them
}