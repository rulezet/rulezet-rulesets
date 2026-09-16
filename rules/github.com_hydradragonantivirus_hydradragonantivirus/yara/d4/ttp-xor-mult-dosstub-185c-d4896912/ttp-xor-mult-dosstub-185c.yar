rule TTP_XOR_MULT_DOSStub_185c {
  strings:
    $key_185c = { 4c 34 [2] 38 2c [2] 7f 2e [2] 38 3f [2] 76 33 [2] 7a 39 [2] 6d 32 [2] 76 7c [2] 4b }

  condition:
    any of them
}