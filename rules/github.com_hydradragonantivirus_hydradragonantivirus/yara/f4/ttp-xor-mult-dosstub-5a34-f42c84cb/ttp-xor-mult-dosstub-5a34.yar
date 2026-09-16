rule TTP_XOR_MULT_DOSStub_5a34 {
  strings:
    $key_5a34 = { 0e 5c [2] 7a 44 [2] 3d 46 [2] 7a 57 [2] 34 5b [2] 38 51 [2] 2f 5a [2] 34 14 [2] 09 }

  condition:
    any of them
}