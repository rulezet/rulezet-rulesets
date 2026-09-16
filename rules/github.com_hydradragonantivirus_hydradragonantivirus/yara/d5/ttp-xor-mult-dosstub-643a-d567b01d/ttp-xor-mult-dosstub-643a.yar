rule TTP_XOR_MULT_DOSStub_643a {
  strings:
    $key_643a = { 30 52 [2] 44 4a [2] 03 48 [2] 44 59 [2] 0a 55 [2] 06 5f [2] 11 54 [2] 0a 1a [2] 37 }

  condition:
    any of them
}