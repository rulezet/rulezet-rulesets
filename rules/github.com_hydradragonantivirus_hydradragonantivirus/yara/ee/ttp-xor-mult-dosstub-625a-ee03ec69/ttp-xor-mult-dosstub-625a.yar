rule TTP_XOR_MULT_DOSStub_625a {
  strings:
    $key_625a = { 36 32 [2] 42 2a [2] 05 28 [2] 42 39 [2] 0c 35 [2] 00 3f [2] 17 34 [2] 0c 7a [2] 31 }

  condition:
    any of them
}