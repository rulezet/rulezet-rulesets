rule TTP_XOR_MULT_DOSStub_1a1a {
  strings:
    $key_1a1a = { 4e 72 [2] 3a 6a [2] 7d 68 [2] 3a 79 [2] 74 75 [2] 78 7f [2] 6f 74 [2] 74 3a [2] 49 }

  condition:
    any of them
}