rule TTP_XOR_MULT_DOSStub_5334 {
  strings:
    $key_5334 = { 07 5c [2] 73 44 [2] 34 46 [2] 73 57 [2] 3d 5b [2] 31 51 [2] 26 5a [2] 3d 14 [2] 00 }

  condition:
    any of them
}