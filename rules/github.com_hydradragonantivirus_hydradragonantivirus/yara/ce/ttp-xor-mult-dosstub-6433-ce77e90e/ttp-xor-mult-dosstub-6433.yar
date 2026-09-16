rule TTP_XOR_MULT_DOSStub_6433 {
  strings:
    $key_6433 = { 30 5b [2] 44 43 [2] 03 41 [2] 44 50 [2] 0a 5c [2] 06 56 [2] 11 5d [2] 0a 13 [2] 37 }

  condition:
    any of them
}