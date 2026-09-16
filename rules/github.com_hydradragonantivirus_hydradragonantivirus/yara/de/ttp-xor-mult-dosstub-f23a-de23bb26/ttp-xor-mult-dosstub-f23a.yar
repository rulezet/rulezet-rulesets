rule TTP_XOR_MULT_DOSStub_f23a {
  strings:
    $key_f23a = { a6 52 [2] d2 4a [2] 95 48 [2] d2 59 [2] 9c 55 [2] 90 5f [2] 87 54 [2] 9c 1a [2] a1 }

  condition:
    any of them
}