rule TTP_XOR_MULT_DOSStub_5319 {
  strings:
    $key_5319 = { 07 71 [2] 73 69 [2] 34 6b [2] 73 7a [2] 3d 76 [2] 31 7c [2] 26 77 [2] 3d 39 [2] 00 }

  condition:
    any of them
}