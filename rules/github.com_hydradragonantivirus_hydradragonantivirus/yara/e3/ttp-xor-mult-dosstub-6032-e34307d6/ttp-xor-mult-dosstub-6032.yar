rule TTP_XOR_MULT_DOSStub_6032 {
  strings:
    $key_6032 = { 34 5a [2] 40 42 [2] 07 40 [2] 40 51 [2] 0e 5d [2] 02 57 [2] 15 5c [2] 0e 12 [2] 33 }

  condition:
    any of them
}