rule TTP_XOR_MULT_DOSStub_5b44 {
  strings:
    $key_5b44 = { 0f 2c [2] 7b 34 [2] 3c 36 [2] 7b 27 [2] 35 2b [2] 39 21 [2] 2e 2a [2] 35 64 [2] 08 }

  condition:
    any of them
}