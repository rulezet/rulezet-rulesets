rule TTP_XOR_MULT_DOSStub_5332 {
  strings:
    $key_5332 = { 07 5a [2] 73 42 [2] 34 40 [2] 73 51 [2] 3d 5d [2] 31 57 [2] 26 5c [2] 3d 12 [2] 00 }

  condition:
    any of them
}