rule TTP_XOR_MULT_DOSStub_f232 {
  strings:
    $key_f232 = { a6 5a [2] d2 42 [2] 95 40 [2] d2 51 [2] 9c 5d [2] 90 57 [2] 87 5c [2] 9c 12 [2] a1 }

  condition:
    any of them
}