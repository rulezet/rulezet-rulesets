rule TTP_XOR_MULT_DOSStub_49f1 {
  strings:
    $key_49f1 = { 1d 99 [2] 69 81 [2] 2e 83 [2] 69 92 [2] 27 9e [2] 2b 94 [2] 3c 9f [2] 27 d1 [2] 1a }

  condition:
    any of them
}