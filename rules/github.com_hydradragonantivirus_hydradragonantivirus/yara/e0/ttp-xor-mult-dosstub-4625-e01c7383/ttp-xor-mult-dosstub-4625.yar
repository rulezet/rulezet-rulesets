rule TTP_XOR_MULT_DOSStub_4625 {
  strings:
    $key_4625 = { 12 4d [2] 66 55 [2] 21 57 [2] 66 46 [2] 28 4a [2] 24 40 [2] 33 4b [2] 28 05 [2] 15 }

  condition:
    any of them
}