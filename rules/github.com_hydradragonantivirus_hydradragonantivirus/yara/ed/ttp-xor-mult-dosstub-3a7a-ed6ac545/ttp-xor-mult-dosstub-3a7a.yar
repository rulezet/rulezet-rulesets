rule TTP_XOR_MULT_DOSStub_3a7a {
  strings:
    $key_3a7a = { 6e 12 [2] 1a 0a [2] 5d 08 [2] 1a 19 [2] 54 15 [2] 58 1f [2] 4f 14 [2] 54 5a [2] 69 }

  condition:
    any of them
}