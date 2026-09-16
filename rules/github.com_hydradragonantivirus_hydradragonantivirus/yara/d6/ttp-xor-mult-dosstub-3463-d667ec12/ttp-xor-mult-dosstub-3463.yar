rule TTP_XOR_MULT_DOSStub_3463 {
  strings:
    $key_3463 = { 60 0b [2] 14 13 [2] 53 11 [2] 14 00 [2] 5a 0c [2] 56 06 [2] 41 0d [2] 5a 43 [2] 67 }

  condition:
    any of them
}