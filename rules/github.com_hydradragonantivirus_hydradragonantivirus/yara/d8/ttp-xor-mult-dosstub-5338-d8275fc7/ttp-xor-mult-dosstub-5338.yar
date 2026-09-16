rule TTP_XOR_MULT_DOSStub_5338 {
  strings:
    $key_5338 = { 07 50 [2] 73 48 [2] 34 4a [2] 73 5b [2] 3d 57 [2] 31 5d [2] 26 56 [2] 3d 18 [2] 00 }

  condition:
    any of them
}