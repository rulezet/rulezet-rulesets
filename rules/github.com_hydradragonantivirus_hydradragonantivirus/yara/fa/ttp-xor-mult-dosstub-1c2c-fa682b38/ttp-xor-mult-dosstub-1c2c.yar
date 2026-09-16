rule TTP_XOR_MULT_DOSStub_1c2c {
  strings:
    $key_1c2c = { 48 44 [2] 3c 5c [2] 7b 5e [2] 3c 4f [2] 72 43 [2] 7e 49 [2] 69 42 [2] 72 0c [2] 4f }

  condition:
    any of them
}