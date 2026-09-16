rule TTP_XOR_MULT_DOSStub_405c {
  strings:
    $key_405c = { 14 34 [2] 60 2c [2] 27 2e [2] 60 3f [2] 2e 33 [2] 22 39 [2] 35 32 [2] 2e 7c [2] 13 }

  condition:
    any of them
}