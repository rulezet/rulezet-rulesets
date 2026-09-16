rule TTP_XOR_MULT_DOSStub_431a {
  strings:
    $key_431a = { 17 72 [2] 63 6a [2] 24 68 [2] 63 79 [2] 2d 75 [2] 21 7f [2] 36 74 [2] 2d 3a [2] 10 }

  condition:
    any of them
}