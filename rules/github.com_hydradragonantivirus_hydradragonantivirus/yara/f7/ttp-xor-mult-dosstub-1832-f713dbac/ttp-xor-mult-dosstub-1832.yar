rule TTP_XOR_MULT_DOSStub_1832 {
  strings:
    $key_1832 = { 4c 5a [2] 38 42 [2] 7f 40 [2] 38 51 [2] 76 5d [2] 7a 57 [2] 6d 5c [2] 76 12 [2] 4b }

  condition:
    any of them
}