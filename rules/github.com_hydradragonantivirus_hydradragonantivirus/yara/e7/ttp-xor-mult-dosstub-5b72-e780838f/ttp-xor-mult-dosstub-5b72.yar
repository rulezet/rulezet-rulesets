rule TTP_XOR_MULT_DOSStub_5b72 {
  strings:
    $key_5b72 = { 0f 1a [2] 7b 02 [2] 3c 00 [2] 7b 11 [2] 35 1d [2] 39 17 [2] 2e 1c [2] 35 52 [2] 08 }

  condition:
    any of them
}