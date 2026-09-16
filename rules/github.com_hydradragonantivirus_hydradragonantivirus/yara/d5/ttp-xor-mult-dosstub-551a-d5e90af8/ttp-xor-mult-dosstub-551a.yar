rule TTP_XOR_MULT_DOSStub_551a {
  strings:
    $key_551a = { 01 72 [2] 75 6a [2] 32 68 [2] 75 79 [2] 3b 75 [2] 37 7f [2] 20 74 [2] 3b 3a [2] 06 }

  condition:
    any of them
}