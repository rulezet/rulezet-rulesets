rule TTP_XOR_MULT_DOSStub_731a {
  strings:
    $key_731a = { 27 72 [2] 53 6a [2] 14 68 [2] 53 79 [2] 1d 75 [2] 11 7f [2] 06 74 [2] 1d 3a [2] 20 }

  condition:
    any of them
}