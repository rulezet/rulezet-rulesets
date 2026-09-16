rule TTP_XOR_MULT_DOSStub_3d59 {
  strings:
    $key_3d59 = { 69 31 [2] 1d 29 [2] 5a 2b [2] 1d 3a [2] 53 36 [2] 5f 3c [2] 48 37 [2] 53 79 [2] 6e }

  condition:
    any of them
}