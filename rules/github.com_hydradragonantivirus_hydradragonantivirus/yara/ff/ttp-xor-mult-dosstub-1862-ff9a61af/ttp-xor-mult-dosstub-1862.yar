rule TTP_XOR_MULT_DOSStub_1862 {
  strings:
    $key_1862 = { 4c 0a [2] 38 12 [2] 7f 10 [2] 38 01 [2] 76 0d [2] 7a 07 [2] 6d 0c [2] 76 42 [2] 4b }

  condition:
    any of them
}