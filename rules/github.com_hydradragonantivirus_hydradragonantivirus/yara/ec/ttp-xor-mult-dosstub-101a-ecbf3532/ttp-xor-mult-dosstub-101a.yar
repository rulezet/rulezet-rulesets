rule TTP_XOR_MULT_DOSStub_101a {
  strings:
    $key_101a = { 44 72 [2] 30 6a [2] 77 68 [2] 30 79 [2] 7e 75 [2] 72 7f [2] 65 74 [2] 7e 3a [2] 43 }

  condition:
    any of them
}