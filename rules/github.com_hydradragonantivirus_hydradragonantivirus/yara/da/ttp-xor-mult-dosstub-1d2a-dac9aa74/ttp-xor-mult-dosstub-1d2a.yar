rule TTP_XOR_MULT_DOSStub_1d2a {
  strings:
    $key_1d2a = { 49 42 [2] 3d 5a [2] 7a 58 [2] 3d 49 [2] 73 45 [2] 7f 4f [2] 68 44 [2] 73 0a [2] 4e }

  condition:
    any of them
}