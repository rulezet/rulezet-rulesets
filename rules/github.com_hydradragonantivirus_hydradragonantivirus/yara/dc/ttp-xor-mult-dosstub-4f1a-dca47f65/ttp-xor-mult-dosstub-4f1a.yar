rule TTP_XOR_MULT_DOSStub_4f1a {
  strings:
    $key_4f1a = { 1b 72 [2] 6f 6a [2] 28 68 [2] 6f 79 [2] 21 75 [2] 2d 7f [2] 3a 74 [2] 21 3a [2] 1c }

  condition:
    any of them
}