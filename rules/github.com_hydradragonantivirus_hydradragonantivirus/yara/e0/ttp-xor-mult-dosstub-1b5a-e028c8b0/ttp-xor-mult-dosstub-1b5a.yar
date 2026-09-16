rule TTP_XOR_MULT_DOSStub_1b5a {
  strings:
    $key_1b5a = { 4f 32 [2] 3b 2a [2] 7c 28 [2] 3b 39 [2] 75 35 [2] 79 3f [2] 6e 34 [2] 75 7a [2] 48 }

  condition:
    any of them
}