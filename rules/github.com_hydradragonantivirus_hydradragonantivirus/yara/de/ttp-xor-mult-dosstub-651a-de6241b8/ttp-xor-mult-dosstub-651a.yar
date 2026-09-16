rule TTP_XOR_MULT_DOSStub_651a {
  strings:
    $key_651a = { 31 72 [2] 45 6a [2] 02 68 [2] 45 79 [2] 0b 75 [2] 07 7f [2] 10 74 [2] 0b 3a [2] 36 }

  condition:
    any of them
}