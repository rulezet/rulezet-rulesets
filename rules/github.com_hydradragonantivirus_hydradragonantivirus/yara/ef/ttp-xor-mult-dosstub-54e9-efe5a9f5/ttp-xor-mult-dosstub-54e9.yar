rule TTP_XOR_MULT_DOSStub_54e9 {
  strings:
    $key_54e9 = { 00 81 [2] 74 99 [2] 33 9b [2] 74 8a [2] 3a 86 [2] 36 8c [2] 21 87 [2] 3a c9 [2] 07 }

  condition:
    any of them
}