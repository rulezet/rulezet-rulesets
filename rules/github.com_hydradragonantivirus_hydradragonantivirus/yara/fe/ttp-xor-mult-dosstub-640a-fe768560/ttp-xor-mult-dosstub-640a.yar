rule TTP_XOR_MULT_DOSStub_640a {
  strings:
    $key_640a = { 30 62 [2] 44 7a [2] 03 78 [2] 44 69 [2] 0a 65 [2] 06 6f [2] 11 64 [2] 0a 2a [2] 37 }

  condition:
    any of them
}