rule TTP_XOR_MULT_DOSStub_415c {
  strings:
    $key_415c = { 15 34 [2] 61 2c [2] 26 2e [2] 61 3f [2] 2f 33 [2] 23 39 [2] 34 32 [2] 2f 7c [2] 12 }

  condition:
    any of them
}