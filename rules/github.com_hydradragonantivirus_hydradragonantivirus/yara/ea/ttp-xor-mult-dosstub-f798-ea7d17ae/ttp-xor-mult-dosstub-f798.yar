rule TTP_XOR_MULT_DOSStub_f798 {
  strings:
    $key_f798 = { a3 f0 [2] d7 e8 [2] 90 ea [2] d7 fb [2] 99 f7 [2] 95 fd [2] 82 f6 [2] 99 b8 [2] a4 }

  condition:
    any of them
}