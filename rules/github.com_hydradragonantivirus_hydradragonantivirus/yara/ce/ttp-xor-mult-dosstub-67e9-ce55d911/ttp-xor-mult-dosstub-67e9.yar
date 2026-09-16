rule TTP_XOR_MULT_DOSStub_67e9 {
  strings:
    $key_67e9 = { 33 81 [2] 47 99 [2] 00 9b [2] 47 8a [2] 09 86 [2] 05 8c [2] 12 87 [2] 09 c9 [2] 34 }

  condition:
    any of them
}