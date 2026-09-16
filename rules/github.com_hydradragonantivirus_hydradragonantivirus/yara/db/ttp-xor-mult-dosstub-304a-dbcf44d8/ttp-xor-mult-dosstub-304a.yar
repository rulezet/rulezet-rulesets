rule TTP_XOR_MULT_DOSStub_304a {
  strings:
    $key_304a = { 64 22 [2] 10 3a [2] 57 38 [2] 10 29 [2] 5e 25 [2] 52 2f [2] 45 24 [2] 5e 6a [2] 63 }

  condition:
    any of them
}