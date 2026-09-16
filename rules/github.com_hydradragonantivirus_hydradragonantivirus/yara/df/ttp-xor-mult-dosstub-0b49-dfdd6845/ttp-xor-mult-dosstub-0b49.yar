rule TTP_XOR_MULT_DOSStub_0b49 {
  strings:
    $key_0b49 = { 5f 21 [2] 2b 39 [2] 6c 3b [2] 2b 2a [2] 65 26 [2] 69 2c [2] 7e 27 [2] 65 69 [2] 58 }

  condition:
    any of them
}