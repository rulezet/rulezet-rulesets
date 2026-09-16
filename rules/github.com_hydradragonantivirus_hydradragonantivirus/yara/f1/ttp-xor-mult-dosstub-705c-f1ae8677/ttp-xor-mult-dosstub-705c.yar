rule TTP_XOR_MULT_DOSStub_705c {
  strings:
    $key_705c = { 24 34 [2] 50 2c [2] 17 2e [2] 50 3f [2] 1e 33 [2] 12 39 [2] 05 32 [2] 1e 7c [2] 23 }

  condition:
    any of them
}