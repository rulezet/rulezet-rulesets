rule TTP_XOR_MULT_DOSStub_2c5c {
  strings:
    $key_2c5c = { 78 34 [2] 0c 2c [2] 4b 2e [2] 0c 3f [2] 42 33 [2] 4e 39 [2] 59 32 [2] 42 7c [2] 7f }

  condition:
    any of them
}