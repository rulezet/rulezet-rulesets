rule TTP_XOR_MULT_DOSStub_54e8 {
  strings:
    $key_54e8 = { 00 80 [2] 74 98 [2] 33 9a [2] 74 8b [2] 3a 87 [2] 36 8d [2] 21 86 [2] 3a c8 [2] 07 }

  condition:
    any of them
}