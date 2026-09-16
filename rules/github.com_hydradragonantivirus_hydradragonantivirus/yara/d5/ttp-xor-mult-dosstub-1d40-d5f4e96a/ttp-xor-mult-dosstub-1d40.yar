rule TTP_XOR_MULT_DOSStub_1d40 {
  strings:
    $key_1d40 = { 49 28 [2] 3d 30 [2] 7a 32 [2] 3d 23 [2] 73 2f [2] 7f 25 [2] 68 2e [2] 73 60 [2] 4e }

  condition:
    any of them
}