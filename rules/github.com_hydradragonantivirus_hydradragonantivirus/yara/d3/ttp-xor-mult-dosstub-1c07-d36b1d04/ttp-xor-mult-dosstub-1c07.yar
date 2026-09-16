rule TTP_XOR_MULT_DOSStub_1c07 {
  strings:
    $key_1c07 = { 48 6f [2] 3c 77 [2] 7b 75 [2] 3c 64 [2] 72 68 [2] 7e 62 [2] 69 69 [2] 72 27 [2] 4f }

  condition:
    any of them
}