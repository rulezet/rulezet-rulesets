rule TTP_XOR_MULT_DOSStub_1a62 {
  strings:
    $key_1a62 = { 4e 0a [2] 3a 12 [2] 7d 10 [2] 3a 01 [2] 74 0d [2] 78 07 [2] 6f 0c [2] 74 42 [2] 49 }

  condition:
    any of them
}