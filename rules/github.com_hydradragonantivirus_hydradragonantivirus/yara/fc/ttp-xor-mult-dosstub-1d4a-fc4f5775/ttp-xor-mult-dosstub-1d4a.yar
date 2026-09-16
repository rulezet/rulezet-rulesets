rule TTP_XOR_MULT_DOSStub_1d4a {
  strings:
    $key_1d4a = { 49 22 [2] 3d 3a [2] 7a 38 [2] 3d 29 [2] 73 25 [2] 7f 2f [2] 68 24 [2] 73 6a [2] 4e }

  condition:
    any of them
}