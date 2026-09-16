rule TTP_XOR_MULT_DOSStub_3d32 {
  strings:
    $key_3d32 = { 69 5a [2] 1d 42 [2] 5a 40 [2] 1d 51 [2] 53 5d [2] 5f 57 [2] 48 5c [2] 53 12 [2] 6e }

  condition:
    any of them
}