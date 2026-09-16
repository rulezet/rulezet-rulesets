rule TTP_XOR_MULT_DOSStub_7068 {
  strings:
    $key_7068 = { 24 00 [2] 50 18 [2] 17 1a [2] 50 0b [2] 1e 07 [2] 12 0d [2] 05 06 [2] 1e 48 [2] 23 }

  condition:
    any of them
}