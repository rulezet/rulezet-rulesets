rule TTP_XOR_MULT_DOSStub_721a {
  strings:
    $key_721a = { 26 72 [2] 52 6a [2] 15 68 [2] 52 79 [2] 1c 75 [2] 10 7f [2] 07 74 [2] 1c 3a [2] 21 }

  condition:
    any of them
}