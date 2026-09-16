rule TTP_XOR_MULT_DOSStub_f7b2 {
  strings:
    $key_f7b2 = { a3 da [2] d7 c2 [2] 90 c0 [2] d7 d1 [2] 99 dd [2] 95 d7 [2] 82 dc [2] 99 92 [2] a4 }

  condition:
    any of them
}