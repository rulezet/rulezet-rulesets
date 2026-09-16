rule TTP_XOR_MULT_DOSStub_225c {
  strings:
    $key_225c = { 76 34 [2] 02 2c [2] 45 2e [2] 02 3f [2] 4c 33 [2] 40 39 [2] 57 32 [2] 4c 7c [2] 71 }

  condition:
    any of them
}