rule TTP_XOR_MULT_DOSStub_3d5a {
  strings:
    $key_3d5a = { 69 32 [2] 1d 2a [2] 5a 28 [2] 1d 39 [2] 53 35 [2] 5f 3f [2] 48 34 [2] 53 7a [2] 6e }

  condition:
    any of them
}