rule TTP_XOR_MULT_DOSStub_3d17 {
  strings:
    $key_3d17 = { 69 7f [2] 1d 67 [2] 5a 65 [2] 1d 74 [2] 53 78 [2] 5f 72 [2] 48 79 [2] 53 37 [2] 6e }

  condition:
    any of them
}