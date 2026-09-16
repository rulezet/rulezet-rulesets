rule TTP_XOR_MULT_DOSStub_7038 {
  strings:
    $key_7038 = { 24 50 [2] 50 48 [2] 17 4a [2] 50 5b [2] 1e 57 [2] 12 5d [2] 05 56 [2] 1e 18 [2] 23 }

  condition:
    any of them
}