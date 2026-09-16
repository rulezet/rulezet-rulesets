rule TTP_XOR_MULT_DOSStub_f259 {
  strings:
    $key_f259 = { a6 31 [2] d2 29 [2] 95 2b [2] d2 3a [2] 9c 36 [2] 90 3c [2] 87 37 [2] 9c 79 [2] a1 }

  condition:
    any of them
}