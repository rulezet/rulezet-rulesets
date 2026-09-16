rule TTP_XOR_MULT_DOSStub_3d39 {
  strings:
    $key_3d39 = { 69 51 [2] 1d 49 [2] 5a 4b [2] 1d 5a [2] 53 56 [2] 5f 5c [2] 48 57 [2] 53 19 [2] 6e }

  condition:
    any of them
}