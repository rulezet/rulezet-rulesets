rule TTP_XOR_MULT_DOSStub_1d44 {
  strings:
    $key_1d44 = { 49 2c [2] 3d 34 [2] 7a 36 [2] 3d 27 [2] 73 2b [2] 7f 21 [2] 68 2a [2] 73 64 [2] 4e }

  condition:
    any of them
}