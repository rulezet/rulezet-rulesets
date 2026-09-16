rule TTP_XOR_MULT_DOSStub_1d57 {
  strings:
    $key_1d57 = { 49 3f [2] 3d 27 [2] 7a 25 [2] 3d 34 [2] 73 38 [2] 7f 32 [2] 68 39 [2] 73 77 [2] 4e }

  condition:
    any of them
}