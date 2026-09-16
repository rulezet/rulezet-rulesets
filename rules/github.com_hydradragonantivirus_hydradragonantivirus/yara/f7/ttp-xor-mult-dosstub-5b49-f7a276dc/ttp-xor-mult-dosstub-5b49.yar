rule TTP_XOR_MULT_DOSStub_5b49 {
  strings:
    $key_5b49 = { 0f 21 [2] 7b 39 [2] 3c 3b [2] 7b 2a [2] 35 26 [2] 39 2c [2] 2e 27 [2] 35 69 [2] 08 }

  condition:
    any of them
}