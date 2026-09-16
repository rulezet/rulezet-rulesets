rule TTP_XOR_MULT_DOSStub_5f1a {
  strings:
    $key_5f1a = { 0b 72 [2] 7f 6a [2] 38 68 [2] 7f 79 [2] 31 75 [2] 3d 7f [2] 2a 74 [2] 31 3a [2] 0c }

  condition:
    any of them
}