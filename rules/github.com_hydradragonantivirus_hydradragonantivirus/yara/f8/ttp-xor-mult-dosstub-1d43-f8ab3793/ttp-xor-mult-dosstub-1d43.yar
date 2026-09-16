rule TTP_XOR_MULT_DOSStub_1d43 {
  strings:
    $key_1d43 = { 49 2b [2] 3d 33 [2] 7a 31 [2] 3d 20 [2] 73 2c [2] 7f 26 [2] 68 2d [2] 73 63 [2] 4e }

  condition:
    any of them
}