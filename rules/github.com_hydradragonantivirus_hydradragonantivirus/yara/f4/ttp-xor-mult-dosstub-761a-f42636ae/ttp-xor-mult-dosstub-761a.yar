rule TTP_XOR_MULT_DOSStub_761a {
  strings:
    $key_761a = { 22 72 [2] 56 6a [2] 11 68 [2] 56 79 [2] 18 75 [2] 14 7f [2] 03 74 [2] 18 3a [2] 25 }

  condition:
    any of them
}