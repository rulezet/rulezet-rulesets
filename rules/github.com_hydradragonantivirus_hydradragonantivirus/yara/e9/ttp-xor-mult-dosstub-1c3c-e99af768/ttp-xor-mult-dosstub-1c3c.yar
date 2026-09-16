rule TTP_XOR_MULT_DOSStub_1c3c {
  strings:
    $key_1c3c = { 48 54 [2] 3c 4c [2] 7b 4e [2] 3c 5f [2] 72 53 [2] 7e 59 [2] 69 52 [2] 72 1c [2] 4f }

  condition:
    any of them
}