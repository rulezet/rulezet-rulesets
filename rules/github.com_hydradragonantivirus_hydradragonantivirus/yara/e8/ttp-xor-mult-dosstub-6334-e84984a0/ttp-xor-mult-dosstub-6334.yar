rule TTP_XOR_MULT_DOSStub_6334 {
  strings:
    $key_6334 = { 37 5c [2] 43 44 [2] 04 46 [2] 43 57 [2] 0d 5b [2] 01 51 [2] 16 5a [2] 0d 14 [2] 30 }

  condition:
    any of them
}