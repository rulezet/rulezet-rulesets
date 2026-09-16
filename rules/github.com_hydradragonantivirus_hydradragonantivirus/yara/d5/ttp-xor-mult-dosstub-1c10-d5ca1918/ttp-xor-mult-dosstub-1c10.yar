rule TTP_XOR_MULT_DOSStub_1c10 {
  strings:
    $key_1c10 = { 48 78 [2] 3c 60 [2] 7b 62 [2] 3c 73 [2] 72 7f [2] 7e 75 [2] 69 7e [2] 72 30 [2] 4f }

  condition:
    any of them
}