rule TTP_XOR_MULT_DOSStub_1c7c {
  strings:
    $key_1c7c = { 48 14 [2] 3c 0c [2] 7b 0e [2] 3c 1f [2] 72 13 [2] 7e 19 [2] 69 12 [2] 72 5c [2] 4f }

  condition:
    any of them
}