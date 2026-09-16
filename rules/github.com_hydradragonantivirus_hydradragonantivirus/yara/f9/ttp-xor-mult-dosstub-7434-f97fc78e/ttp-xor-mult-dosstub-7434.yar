rule TTP_XOR_MULT_DOSStub_7434 {
  strings:
    $key_7434 = { 20 5c [2] 54 44 [2] 13 46 [2] 54 57 [2] 1a 5b [2] 16 51 [2] 01 5a [2] 1a 14 [2] 27 }

  condition:
    any of them
}