rule TTP_XOR_MULT_DOSStub_5141 {
  strings:
    $key_5141 = { 05 29 [2] 71 31 [2] 36 33 [2] 71 22 [2] 3f 2e [2] 33 24 [2] 24 2f [2] 3f 61 [2] 02 }

  condition:
    any of them
}