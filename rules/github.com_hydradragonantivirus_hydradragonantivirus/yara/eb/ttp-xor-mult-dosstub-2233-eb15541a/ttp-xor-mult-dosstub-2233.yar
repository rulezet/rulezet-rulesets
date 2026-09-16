rule TTP_XOR_MULT_DOSStub_2233 {
  strings:
    $key_2233 = { 76 5b [2] 02 43 [2] 45 41 [2] 02 50 [2] 4c 5c [2] 40 56 [2] 57 5d [2] 4c 13 [2] 71 }

  condition:
    any of them
}