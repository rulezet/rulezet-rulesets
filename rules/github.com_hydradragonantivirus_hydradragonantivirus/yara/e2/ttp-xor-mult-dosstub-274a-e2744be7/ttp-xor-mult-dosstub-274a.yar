rule TTP_XOR_MULT_DOSStub_274a {
  strings:
    $key_274a = { 73 22 [2] 07 3a [2] 40 38 [2] 07 29 [2] 49 25 [2] 45 2f [2] 52 24 [2] 49 6a [2] 74 }

  condition:
    any of them
}