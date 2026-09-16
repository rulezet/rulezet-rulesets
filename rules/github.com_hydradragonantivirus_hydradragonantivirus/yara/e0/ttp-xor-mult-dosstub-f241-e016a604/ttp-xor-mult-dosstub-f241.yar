rule TTP_XOR_MULT_DOSStub_f241 {
  strings:
    $key_f241 = { a6 29 [2] d2 31 [2] 95 33 [2] d2 22 [2] 9c 2e [2] 90 24 [2] 87 2f [2] 9c 61 [2] a1 }

  condition:
    any of them
}