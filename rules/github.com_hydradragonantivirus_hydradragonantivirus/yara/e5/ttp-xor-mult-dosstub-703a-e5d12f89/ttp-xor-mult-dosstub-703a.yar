rule TTP_XOR_MULT_DOSStub_703a {
  strings:
    $key_703a = { 24 52 [2] 50 4a [2] 17 48 [2] 50 59 [2] 1e 55 [2] 12 5f [2] 05 54 [2] 1e 1a [2] 23 }

  condition:
    any of them
}