rule TTP_XOR_MULT_DOSStub_6833 {
  strings:
    $key_6833 = { 3c 5b [2] 48 43 [2] 0f 41 [2] 48 50 [2] 06 5c [2] 0a 56 [2] 1d 5d [2] 06 13 [2] 3b }

  condition:
    any of them
}