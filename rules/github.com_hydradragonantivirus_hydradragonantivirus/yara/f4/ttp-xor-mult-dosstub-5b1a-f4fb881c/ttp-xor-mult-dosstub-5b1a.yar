rule TTP_XOR_MULT_DOSStub_5b1a {
  strings:
    $key_5b1a = { 0f 72 [2] 7b 6a [2] 3c 68 [2] 7b 79 [2] 35 75 [2] 39 7f [2] 2e 74 [2] 35 3a [2] 08 }

  condition:
    any of them
}