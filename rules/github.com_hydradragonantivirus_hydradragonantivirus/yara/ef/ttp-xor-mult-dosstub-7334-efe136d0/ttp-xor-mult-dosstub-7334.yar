rule TTP_XOR_MULT_DOSStub_7334 {
  strings:
    $key_7334 = { 27 5c [2] 53 44 [2] 14 46 [2] 53 57 [2] 1d 5b [2] 11 51 [2] 06 5a [2] 1d 14 [2] 20 }

  condition:
    any of them
}