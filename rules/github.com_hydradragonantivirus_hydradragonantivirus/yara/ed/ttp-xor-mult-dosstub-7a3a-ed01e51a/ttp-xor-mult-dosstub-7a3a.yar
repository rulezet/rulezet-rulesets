rule TTP_XOR_MULT_DOSStub_7a3a {
  strings:
    $key_7a3a = { 2e 52 [2] 5a 4a [2] 1d 48 [2] 5a 59 [2] 14 55 [2] 18 5f [2] 0f 54 [2] 14 1a [2] 29 }

  condition:
    any of them
}