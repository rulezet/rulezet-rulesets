rule TTP_XOR_MULT_DOSStub_3429 {
  strings:
    $key_3429 = { 60 41 [2] 14 59 [2] 53 5b [2] 14 4a [2] 5a 46 [2] 56 4c [2] 41 47 [2] 5a 09 [2] 67 }

  condition:
    any of them
}