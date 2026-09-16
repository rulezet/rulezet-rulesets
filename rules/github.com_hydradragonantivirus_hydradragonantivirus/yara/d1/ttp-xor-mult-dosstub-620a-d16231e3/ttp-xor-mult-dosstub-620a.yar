rule TTP_XOR_MULT_DOSStub_620a {
  strings:
    $key_620a = { 36 62 [2] 42 7a [2] 05 78 [2] 42 69 [2] 0c 65 [2] 00 6f [2] 17 64 [2] 0c 2a [2] 31 }

  condition:
    any of them
}