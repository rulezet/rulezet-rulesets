rule TTP_XOR_MULT_DOSStub_5d2c {
  strings:
    $key_5d2c = { 09 44 [2] 7d 5c [2] 3a 5e [2] 7d 4f [2] 33 43 [2] 3f 49 [2] 28 42 [2] 33 0c [2] 0e }

  condition:
    any of them
}