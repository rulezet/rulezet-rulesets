rule TTP_XOR_MULT_DOSStub_1b2c {
  strings:
    $key_1b2c = { 4f 44 [2] 3b 5c [2] 7c 5e [2] 3b 4f [2] 75 43 [2] 79 49 [2] 6e 42 [2] 75 0c [2] 48 }

  condition:
    any of them
}