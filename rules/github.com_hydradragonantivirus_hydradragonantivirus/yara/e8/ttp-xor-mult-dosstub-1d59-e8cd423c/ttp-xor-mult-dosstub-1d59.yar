rule TTP_XOR_MULT_DOSStub_1d59 {
  strings:
    $key_1d59 = { 49 31 [2] 3d 29 [2] 7a 2b [2] 3d 3a [2] 73 36 [2] 7f 3c [2] 68 37 [2] 73 79 [2] 4e }

  condition:
    any of them
}