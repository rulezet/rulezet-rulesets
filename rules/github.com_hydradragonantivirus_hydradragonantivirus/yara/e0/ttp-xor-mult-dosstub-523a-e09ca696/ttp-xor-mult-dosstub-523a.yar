rule TTP_XOR_MULT_DOSStub_523a {
  strings:
    $key_523a = { 06 52 [2] 72 4a [2] 35 48 [2] 72 59 [2] 3c 55 [2] 30 5f [2] 27 54 [2] 3c 1a [2] 01 }

  condition:
    any of them
}