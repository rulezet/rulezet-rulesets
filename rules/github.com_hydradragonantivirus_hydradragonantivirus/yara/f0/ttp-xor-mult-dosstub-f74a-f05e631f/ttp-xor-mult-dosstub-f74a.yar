rule TTP_XOR_MULT_DOSStub_f74a {
  strings:
    $key_f74a = { a3 22 [2] d7 3a [2] 90 38 [2] d7 29 [2] 99 25 [2] 95 2f [2] 82 24 [2] 99 6a [2] a4 }

  condition:
    any of them
}