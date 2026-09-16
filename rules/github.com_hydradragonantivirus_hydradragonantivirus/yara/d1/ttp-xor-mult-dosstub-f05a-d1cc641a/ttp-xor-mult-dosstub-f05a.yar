rule TTP_XOR_MULT_DOSStub_f05a {
  strings:
    $key_f05a = { a4 32 [2] d0 2a [2] 97 28 [2] d0 39 [2] 9e 35 [2] 92 3f [2] 85 34 [2] 9e 7a [2] a3 }

  condition:
    any of them
}