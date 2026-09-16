rule TTP_XOR_MULT_DOSStub_3a5c {
  strings:
    $key_3a5c = { 6e 34 [2] 1a 2c [2] 5d 2e [2] 1a 3f [2] 54 33 [2] 58 39 [2] 4f 32 [2] 54 7c [2] 69 }

  condition:
    any of them
}