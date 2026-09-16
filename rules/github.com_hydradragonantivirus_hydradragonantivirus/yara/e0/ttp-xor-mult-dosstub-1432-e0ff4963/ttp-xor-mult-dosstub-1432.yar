rule TTP_XOR_MULT_DOSStub_1432 {
  strings:
    $key_1432 = { 40 5a [2] 34 42 [2] 73 40 [2] 34 51 [2] 7a 5d [2] 76 57 [2] 61 5c [2] 7a 12 [2] 47 }

  condition:
    any of them
}