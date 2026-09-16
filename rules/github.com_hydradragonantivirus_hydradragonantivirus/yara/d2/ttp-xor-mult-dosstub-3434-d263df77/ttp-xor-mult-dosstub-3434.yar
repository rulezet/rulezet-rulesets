rule TTP_XOR_MULT_DOSStub_3434 {
  strings:
    $key_3434 = { 60 5c [2] 14 44 [2] 53 46 [2] 14 57 [2] 5a 5b [2] 56 51 [2] 41 5a [2] 5a 14 [2] 67 }

  condition:
    any of them
}