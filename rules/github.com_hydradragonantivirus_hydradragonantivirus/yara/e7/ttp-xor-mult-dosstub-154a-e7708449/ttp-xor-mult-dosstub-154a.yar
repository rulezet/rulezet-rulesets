rule TTP_XOR_MULT_DOSStub_154a {
  strings:
    $key_154a = { 41 22 [2] 35 3a [2] 72 38 [2] 35 29 [2] 7b 25 [2] 77 2f [2] 60 24 [2] 7b 6a [2] 46 }

  condition:
    any of them
}