rule TTP_XOR_MULT_DOSStub_1c51 {
  strings:
    $key_1c51 = { 48 39 [2] 3c 21 [2] 7b 23 [2] 3c 32 [2] 72 3e [2] 7e 34 [2] 69 3f [2] 72 71 [2] 4f }

  condition:
    any of them
}