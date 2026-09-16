rule TTP_XOR_MULT_DOSStub_2132 {
  strings:
    $key_2132 = { 75 5a [2] 01 42 [2] 46 40 [2] 01 51 [2] 4f 5d [2] 43 57 [2] 54 5c [2] 4f 12 [2] 72 }

  condition:
    any of them
}