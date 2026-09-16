rule TTP_XOR_MULT_DOSStub_5304 {
  strings:
    $key_5304 = { 07 6c [2] 73 74 [2] 34 76 [2] 73 67 [2] 3d 6b [2] 31 61 [2] 26 6a [2] 3d 24 [2] 00 }

  condition:
    any of them
}