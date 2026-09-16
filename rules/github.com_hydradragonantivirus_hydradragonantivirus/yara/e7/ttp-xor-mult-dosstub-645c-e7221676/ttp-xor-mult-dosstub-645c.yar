rule TTP_XOR_MULT_DOSStub_645c {
  strings:
    $key_645c = { 30 34 [2] 44 2c [2] 03 2e [2] 44 3f [2] 0a 33 [2] 06 39 [2] 11 32 [2] 0a 7c [2] 37 }

  condition:
    any of them
}