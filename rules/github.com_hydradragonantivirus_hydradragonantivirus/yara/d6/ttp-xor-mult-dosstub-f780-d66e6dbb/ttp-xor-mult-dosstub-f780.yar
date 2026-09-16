rule TTP_XOR_MULT_DOSStub_f780 {
  strings:
    $key_f780 = { a3 e8 [2] d7 f0 [2] 90 f2 [2] d7 e3 [2] 99 ef [2] 95 e5 [2] 82 ee [2] 99 a0 [2] a4 }

  condition:
    any of them
}