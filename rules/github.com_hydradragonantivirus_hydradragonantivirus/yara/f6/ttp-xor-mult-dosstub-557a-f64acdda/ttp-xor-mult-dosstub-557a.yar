rule TTP_XOR_MULT_DOSStub_557a {
  strings:
    $key_557a = { 01 12 [2] 75 0a [2] 32 08 [2] 75 19 [2] 3b 15 [2] 37 1f [2] 20 14 [2] 3b 5a [2] 06 }

  condition:
    any of them
}