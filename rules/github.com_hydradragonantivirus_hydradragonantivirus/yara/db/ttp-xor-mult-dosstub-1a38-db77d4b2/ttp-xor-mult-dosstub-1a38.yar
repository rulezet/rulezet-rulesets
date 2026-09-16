rule TTP_XOR_MULT_DOSStub_1a38 {
  strings:
    $key_1a38 = { 4e 50 [2] 3a 48 [2] 7d 4a [2] 3a 5b [2] 74 57 [2] 78 5d [2] 6f 56 [2] 74 18 [2] 49 }

  condition:
    any of them
}