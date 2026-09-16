rule TTP_XOR_MULT_DOSStub_075c {
  strings:
    $key_075c = { 53 34 [2] 27 2c [2] 60 2e [2] 27 3f [2] 69 33 [2] 65 39 [2] 72 32 [2] 69 7c [2] 54 }

  condition:
    any of them
}