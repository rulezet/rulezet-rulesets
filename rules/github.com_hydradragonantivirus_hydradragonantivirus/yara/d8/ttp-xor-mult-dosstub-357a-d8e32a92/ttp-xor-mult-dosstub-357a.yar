rule TTP_XOR_MULT_DOSStub_357a {
  strings:
    $key_357a = { 61 12 [2] 15 0a [2] 52 08 [2] 15 19 [2] 5b 15 [2] 57 1f [2] 40 14 [2] 5b 5a [2] 66 }

  condition:
    any of them
}