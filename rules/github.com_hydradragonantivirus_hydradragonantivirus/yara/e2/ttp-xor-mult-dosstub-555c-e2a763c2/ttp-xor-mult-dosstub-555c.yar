rule TTP_XOR_MULT_DOSStub_555c {
  strings:
    $key_555c = { 01 34 [2] 75 2c [2] 32 2e [2] 75 3f [2] 3b 33 [2] 37 39 [2] 20 32 [2] 3b 7c [2] 06 }

  condition:
    any of them
}