rule TTP_XOR_MULT_DOSStub_1c50 {
  strings:
    $key_1c50 = { 48 38 [2] 3c 20 [2] 7b 22 [2] 3c 33 [2] 72 3f [2] 7e 35 [2] 69 3e [2] 72 70 [2] 4f }

  condition:
    any of them
}