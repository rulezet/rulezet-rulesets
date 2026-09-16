rule TTP_XOR_MULT_DOSStub_0b2c {
  strings:
    $key_0b2c = { 5f 44 [2] 2b 5c [2] 6c 5e [2] 2b 4f [2] 65 43 [2] 69 49 [2] 7e 42 [2] 65 0c [2] 58 }

  condition:
    any of them
}