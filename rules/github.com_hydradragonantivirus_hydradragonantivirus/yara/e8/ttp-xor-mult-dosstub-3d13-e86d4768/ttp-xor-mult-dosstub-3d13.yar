rule TTP_XOR_MULT_DOSStub_3d13 {
  strings:
    $key_3d13 = { 69 7b [2] 1d 63 [2] 5a 61 [2] 1d 70 [2] 53 7c [2] 5f 76 [2] 48 7d [2] 53 33 [2] 6e }

  condition:
    any of them
}