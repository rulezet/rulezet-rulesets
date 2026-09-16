rule TTP_XOR_MULT_DOSStub_155c {
  strings:
    $key_155c = { 41 34 [2] 35 2c [2] 72 2e [2] 35 3f [2] 7b 33 [2] 77 39 [2] 60 32 [2] 7b 7c [2] 46 }

  condition:
    any of them
}