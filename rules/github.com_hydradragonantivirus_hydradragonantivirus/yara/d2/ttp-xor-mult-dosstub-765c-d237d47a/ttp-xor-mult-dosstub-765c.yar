rule TTP_XOR_MULT_DOSStub_765c {
  strings:
    $key_765c = { 22 34 [2] 56 2c [2] 11 2e [2] 56 3f [2] 18 33 [2] 14 39 [2] 03 32 [2] 18 7c [2] 25 }

  condition:
    any of them
}