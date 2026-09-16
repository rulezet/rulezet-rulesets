rule TTP_XOR_MULT_DOSStub_70e7 {
  strings:
    $key_70e7 = { 24 8f [2] 50 97 [2] 17 95 [2] 50 84 [2] 1e 88 [2] 12 82 [2] 05 89 [2] 1e c7 [2] 23 }

  condition:
    any of them
}