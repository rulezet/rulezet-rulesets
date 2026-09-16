rule TTP_XOR_MULT_DOSStub_1c11 {
  strings:
    $key_1c11 = { 48 79 [2] 3c 61 [2] 7b 63 [2] 3c 72 [2] 72 7e [2] 7e 74 [2] 69 7f [2] 72 31 [2] 4f }

  condition:
    any of them
}