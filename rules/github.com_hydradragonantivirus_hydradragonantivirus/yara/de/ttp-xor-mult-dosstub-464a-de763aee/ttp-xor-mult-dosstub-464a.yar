rule TTP_XOR_MULT_DOSStub_464a {
  strings:
    $key_464a = { 12 22 [2] 66 3a [2] 21 38 [2] 66 29 [2] 28 25 [2] 24 2f [2] 33 24 [2] 28 6a [2] 15 }

  condition:
    any of them
}