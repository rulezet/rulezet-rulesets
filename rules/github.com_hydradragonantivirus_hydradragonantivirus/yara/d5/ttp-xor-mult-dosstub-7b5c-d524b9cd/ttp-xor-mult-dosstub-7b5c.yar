rule TTP_XOR_MULT_DOSStub_7b5c {
  strings:
    $key_7b5c = { 2f 34 [2] 5b 2c [2] 1c 2e [2] 5b 3f [2] 15 33 [2] 19 39 [2] 0e 32 [2] 15 7c [2] 28 }

  condition:
    any of them
}