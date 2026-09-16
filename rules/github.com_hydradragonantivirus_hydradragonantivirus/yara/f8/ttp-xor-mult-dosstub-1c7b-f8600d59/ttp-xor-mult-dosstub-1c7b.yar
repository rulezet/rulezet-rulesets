rule TTP_XOR_MULT_DOSStub_1c7b {
  strings:
    $key_1c7b = { 48 13 [2] 3c 0b [2] 7b 09 [2] 3c 18 [2] 72 14 [2] 7e 1e [2] 69 15 [2] 72 5b [2] 4f }

  condition:
    any of them
}