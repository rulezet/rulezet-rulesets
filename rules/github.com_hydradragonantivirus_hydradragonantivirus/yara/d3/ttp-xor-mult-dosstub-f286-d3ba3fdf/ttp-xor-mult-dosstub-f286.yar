rule TTP_XOR_MULT_DOSStub_f286 {
  strings:
    $key_f286 = { a6 ee [2] d2 f6 [2] 95 f4 [2] d2 e5 [2] 9c e9 [2] 90 e3 [2] 87 e8 [2] 9c a6 [2] a1 }

  condition:
    any of them
}