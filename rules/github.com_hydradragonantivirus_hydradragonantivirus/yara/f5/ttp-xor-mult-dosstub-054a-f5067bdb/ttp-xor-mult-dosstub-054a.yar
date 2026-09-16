rule TTP_XOR_MULT_DOSStub_054a {
  strings:
    $key_054a = { 51 22 [2] 25 3a [2] 62 38 [2] 25 29 [2] 6b 25 [2] 67 2f [2] 70 24 [2] 6b 6a [2] 56 }

  condition:
    any of them
}