rule TTP_XOR_MULT_DOSStub_4033 {
  strings:
    $key_4033 = { 14 5b [2] 60 43 [2] 27 41 [2] 60 50 [2] 2e 5c [2] 22 56 [2] 35 5d [2] 2e 13 [2] 13 }

  condition:
    any of them
}