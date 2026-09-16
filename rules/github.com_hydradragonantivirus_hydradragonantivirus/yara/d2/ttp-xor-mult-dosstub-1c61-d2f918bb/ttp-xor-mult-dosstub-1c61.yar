rule TTP_XOR_MULT_DOSStub_1c61 {
  strings:
    $key_1c61 = { 48 09 [2] 3c 11 [2] 7b 13 [2] 3c 02 [2] 72 0e [2] 7e 04 [2] 69 0f [2] 72 41 [2] 4f }

  condition:
    any of them
}