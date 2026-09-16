rule TTP_XOR_MULT_DOSStub_452a {
  strings:
    $key_452a = { 11 42 [2] 65 5a [2] 22 58 [2] 65 49 [2] 2b 45 [2] 27 4f [2] 30 44 [2] 2b 0a [2] 16 }

  condition:
    any of them
}