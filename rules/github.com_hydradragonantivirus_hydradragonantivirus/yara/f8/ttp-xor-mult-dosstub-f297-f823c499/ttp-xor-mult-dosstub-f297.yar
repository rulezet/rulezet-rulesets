rule TTP_XOR_MULT_DOSStub_f297 {
  strings:
    $key_f297 = { a6 ff [2] d2 e7 [2] 95 e5 [2] d2 f4 [2] 9c f8 [2] 90 f2 [2] 87 f9 [2] 9c b7 [2] a1 }

  condition:
    any of them
}