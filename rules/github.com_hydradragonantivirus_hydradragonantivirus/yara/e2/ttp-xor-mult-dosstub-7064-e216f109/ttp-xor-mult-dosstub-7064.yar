rule TTP_XOR_MULT_DOSStub_7064 {
  strings:
    $key_7064 = { 24 0c [2] 50 14 [2] 17 16 [2] 50 07 [2] 1e 0b [2] 12 01 [2] 05 0a [2] 1e 44 [2] 23 }

  condition:
    any of them
}