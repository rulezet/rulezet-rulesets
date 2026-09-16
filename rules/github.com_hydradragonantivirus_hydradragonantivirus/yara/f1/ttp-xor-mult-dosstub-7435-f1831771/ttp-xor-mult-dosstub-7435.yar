rule TTP_XOR_MULT_DOSStub_7435 {
  strings:
    $key_7435 = { 20 5d [2] 54 45 [2] 13 47 [2] 54 56 [2] 1a 5a [2] 16 50 [2] 01 5b [2] 1a 15 [2] 27 }

  condition:
    any of them
}