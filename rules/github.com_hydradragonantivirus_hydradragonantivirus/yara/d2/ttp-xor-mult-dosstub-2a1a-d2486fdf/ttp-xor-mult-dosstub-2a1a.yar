rule TTP_XOR_MULT_DOSStub_2a1a {
  strings:
    $key_2a1a = { 7e 72 [2] 0a 6a [2] 4d 68 [2] 0a 79 [2] 44 75 [2] 48 7f [2] 5f 74 [2] 44 3a [2] 79 }

  condition:
    any of them
}