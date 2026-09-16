rule TTP_XOR_MULT_DOSStub_1c56 {
  strings:
    $key_1c56 = { 48 3e [2] 3c 26 [2] 7b 24 [2] 3c 35 [2] 72 39 [2] 7e 33 [2] 69 38 [2] 72 76 [2] 4f }

  condition:
    any of them
}