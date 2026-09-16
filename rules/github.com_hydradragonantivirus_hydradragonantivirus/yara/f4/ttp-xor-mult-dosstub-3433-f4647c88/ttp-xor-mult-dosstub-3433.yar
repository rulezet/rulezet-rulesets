rule TTP_XOR_MULT_DOSStub_3433 {
  strings:
    $key_3433 = { 60 5b [2] 14 43 [2] 53 41 [2] 14 50 [2] 5a 5c [2] 56 56 [2] 41 5d [2] 5a 13 [2] 67 }

  condition:
    any of them
}