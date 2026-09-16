rule TTP_XOR_MULT_DOSStub_3a1a {
  strings:
    $key_3a1a = { 6e 72 [2] 1a 6a [2] 5d 68 [2] 1a 79 [2] 54 75 [2] 58 7f [2] 4f 74 [2] 54 3a [2] 69 }

  condition:
    any of them
}