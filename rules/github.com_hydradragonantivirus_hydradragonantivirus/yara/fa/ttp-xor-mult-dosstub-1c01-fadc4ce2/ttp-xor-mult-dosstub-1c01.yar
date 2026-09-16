rule TTP_XOR_MULT_DOSStub_1c01 {
  strings:
    $key_1c01 = { 48 69 [2] 3c 71 [2] 7b 73 [2] 3c 62 [2] 72 6e [2] 7e 64 [2] 69 6f [2] 72 21 [2] 4f }

  condition:
    any of them
}