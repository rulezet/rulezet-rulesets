rule TTP_XOR_MULT_DOSStub_1b1a {
  strings:
    $key_1b1a = { 4f 72 [2] 3b 6a [2] 7c 68 [2] 3b 79 [2] 75 75 [2] 79 7f [2] 6e 74 [2] 75 3a [2] 48 }

  condition:
    any of them
}