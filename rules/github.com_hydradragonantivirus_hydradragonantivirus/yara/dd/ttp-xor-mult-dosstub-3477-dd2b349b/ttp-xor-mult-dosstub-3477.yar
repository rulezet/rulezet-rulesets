rule TTP_XOR_MULT_DOSStub_3477 {
  strings:
    $key_3477 = { 60 1f [2] 14 07 [2] 53 05 [2] 14 14 [2] 5a 18 [2] 56 12 [2] 41 19 [2] 5a 57 [2] 67 }

  condition:
    any of them
}