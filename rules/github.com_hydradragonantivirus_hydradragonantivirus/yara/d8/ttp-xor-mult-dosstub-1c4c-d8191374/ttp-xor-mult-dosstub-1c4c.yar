rule TTP_XOR_MULT_DOSStub_1c4c {
  strings:
    $key_1c4c = { 48 24 [2] 3c 3c [2] 7b 3e [2] 3c 2f [2] 72 23 [2] 7e 29 [2] 69 22 [2] 72 6c [2] 4f }

  condition:
    any of them
}