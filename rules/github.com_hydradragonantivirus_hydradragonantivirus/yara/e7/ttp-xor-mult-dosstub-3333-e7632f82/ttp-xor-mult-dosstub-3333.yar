rule TTP_XOR_MULT_DOSStub_3333 {
  strings:
    $key_3333 = { 67 5b [2] 13 43 [2] 54 41 [2] 13 50 [2] 5d 5c [2] 51 56 [2] 46 5d [2] 5d 13 [2] 60 }

  condition:
    any of them
}