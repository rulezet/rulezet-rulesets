rule TTP_XOR_MULT_DOSStub_f75a {
  strings:
    $key_f75a = { a3 32 [2] d7 2a [2] 90 28 [2] d7 39 [2] 99 35 [2] 95 3f [2] 82 34 [2] 99 7a [2] a4 }

  condition:
    any of them
}