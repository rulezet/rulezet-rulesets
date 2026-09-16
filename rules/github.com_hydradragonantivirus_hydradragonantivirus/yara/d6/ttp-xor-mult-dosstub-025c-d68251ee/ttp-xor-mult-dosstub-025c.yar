rule TTP_XOR_MULT_DOSStub_025c {
  strings:
    $key_025c = { 56 34 [2] 22 2c [2] 65 2e [2] 22 3f [2] 6c 33 [2] 60 39 [2] 77 32 [2] 6c 7c [2] 51 }

  condition:
    any of them
}