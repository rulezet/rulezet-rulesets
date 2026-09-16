rule TTP_XOR_MULT_DOSStub_f746 {
  strings:
    $key_f746 = { a3 2e [2] d7 36 [2] 90 34 [2] d7 25 [2] 99 29 [2] 95 23 [2] 82 28 [2] 99 66 [2] a4 }

  condition:
    any of them
}