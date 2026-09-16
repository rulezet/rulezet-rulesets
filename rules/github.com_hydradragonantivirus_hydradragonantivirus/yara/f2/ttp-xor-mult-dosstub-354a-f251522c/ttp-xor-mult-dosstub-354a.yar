rule TTP_XOR_MULT_DOSStub_354a {
  strings:
    $key_354a = { 61 22 [2] 15 3a [2] 52 38 [2] 15 29 [2] 5b 25 [2] 57 2f [2] 40 24 [2] 5b 6a [2] 66 }

  condition:
    any of them
}