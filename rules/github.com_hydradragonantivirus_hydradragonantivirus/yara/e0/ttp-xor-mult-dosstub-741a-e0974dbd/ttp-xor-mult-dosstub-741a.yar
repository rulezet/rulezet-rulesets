rule TTP_XOR_MULT_DOSStub_741a {
  strings:
    $key_741a = { 20 72 [2] 54 6a [2] 13 68 [2] 54 79 [2] 1a 75 [2] 16 7f [2] 01 74 [2] 1a 3a [2] 27 }

  condition:
    any of them
}