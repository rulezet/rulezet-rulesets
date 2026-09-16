rule TTP_XOR_MULT_DOSStub_1c00 {
  strings:
    $key_1c00 = { 48 68 [2] 3c 70 [2] 7b 72 [2] 3c 63 [2] 72 6f [2] 7e 65 [2] 69 6e [2] 72 20 [2] 4f }

  condition:
    any of them
}