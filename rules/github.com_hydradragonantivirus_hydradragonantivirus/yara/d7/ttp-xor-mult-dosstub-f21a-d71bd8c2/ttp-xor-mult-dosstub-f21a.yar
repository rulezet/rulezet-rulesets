rule TTP_XOR_MULT_DOSStub_f21a {
  strings:
    $key_f21a = { a6 72 [2] d2 6a [2] 95 68 [2] d2 79 [2] 9c 75 [2] 90 7f [2] 87 74 [2] 9c 3a [2] a1 }

  condition:
    any of them
}