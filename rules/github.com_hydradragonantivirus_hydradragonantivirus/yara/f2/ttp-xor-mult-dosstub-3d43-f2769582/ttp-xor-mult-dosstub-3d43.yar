rule TTP_XOR_MULT_DOSStub_3d43 {
  strings:
    $key_3d43 = { 69 2b [2] 1d 33 [2] 5a 31 [2] 1d 20 [2] 53 2c [2] 5f 26 [2] 48 2d [2] 53 63 [2] 6e }

  condition:
    any of them
}