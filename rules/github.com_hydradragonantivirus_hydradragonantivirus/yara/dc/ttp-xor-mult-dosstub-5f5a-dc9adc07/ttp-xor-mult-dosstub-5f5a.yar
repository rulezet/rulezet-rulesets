rule TTP_XOR_MULT_DOSStub_5f5a {
  strings:
    $key_5f5a = { 0b 32 [2] 7f 2a [2] 38 28 [2] 7f 39 [2] 31 35 [2] 3d 3f [2] 2a 34 [2] 31 7a [2] 0c }

  condition:
    any of them
}