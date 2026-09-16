rule TTP_XOR_MULT_DOSStub_f7c5 {
  strings:
    $key_f7c5 = { a3 ad [2] d7 b5 [2] 90 b7 [2] d7 a6 [2] 99 aa [2] 95 a0 [2] 82 ab [2] 99 e5 [2] a4 }

  condition:
    any of them
}