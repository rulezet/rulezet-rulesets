rule TTP_XOR_MULT_DOSStub_152a {
  strings:
    $key_152a = { 41 42 [2] 35 5a [2] 72 58 [2] 35 49 [2] 7b 45 [2] 77 4f [2] 60 44 [2] 7b 0a [2] 46 }

  condition:
    any of them
}