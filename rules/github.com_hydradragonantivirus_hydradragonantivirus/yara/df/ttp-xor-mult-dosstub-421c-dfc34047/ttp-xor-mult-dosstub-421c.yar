rule TTP_XOR_MULT_DOSStub_421c {
  strings:
    $key_421c = { 16 74 [2] 62 6c [2] 25 6e [2] 62 7f [2] 2c 73 [2] 20 79 [2] 37 72 [2] 2c 3c [2] 11 }

  condition:
    any of them
}