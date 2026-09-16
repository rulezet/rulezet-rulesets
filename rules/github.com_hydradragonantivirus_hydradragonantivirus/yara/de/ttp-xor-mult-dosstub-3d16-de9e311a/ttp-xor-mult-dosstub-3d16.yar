rule TTP_XOR_MULT_DOSStub_3d16 {
  strings:
    $key_3d16 = { 69 7e [2] 1d 66 [2] 5a 64 [2] 1d 75 [2] 53 79 [2] 5f 73 [2] 48 78 [2] 53 36 [2] 6e }

  condition:
    any of them
}