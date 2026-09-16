rule TTP_XOR_MULT_DOSStub_625c {
  strings:
    $key_625c = { 36 34 [2] 42 2c [2] 05 2e [2] 42 3f [2] 0c 33 [2] 00 39 [2] 17 32 [2] 0c 7c [2] 31 }

  condition:
    any of them
}