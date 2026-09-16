rule TTP_XOR_MULT_DOSStub_647a {
  strings:
    $key_647a = { 30 12 [2] 44 0a [2] 03 08 [2] 44 19 [2] 0a 15 [2] 06 1f [2] 11 14 [2] 0a 5a [2] 37 }

  condition:
    any of them
}