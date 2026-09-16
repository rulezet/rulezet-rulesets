rule TTP_XOR_MULT_DOSStub_425c {
  strings:
    $key_425c = { 16 34 [2] 62 2c [2] 25 2e [2] 62 3f [2] 2c 33 [2] 20 39 [2] 37 32 [2] 2c 7c [2] 11 }

  condition:
    any of them
}