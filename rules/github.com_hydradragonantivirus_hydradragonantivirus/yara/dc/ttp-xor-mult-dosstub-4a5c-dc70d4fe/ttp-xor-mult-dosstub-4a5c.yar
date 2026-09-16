rule TTP_XOR_MULT_DOSStub_4a5c {
  strings:
    $key_4a5c = { 1e 34 [2] 6a 2c [2] 2d 2e [2] 6a 3f [2] 24 33 [2] 28 39 [2] 3f 32 [2] 24 7c [2] 19 }

  condition:
    any of them
}