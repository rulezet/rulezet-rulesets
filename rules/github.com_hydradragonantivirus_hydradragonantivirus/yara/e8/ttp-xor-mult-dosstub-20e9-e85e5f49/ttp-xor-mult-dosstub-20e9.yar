rule TTP_XOR_MULT_DOSStub_20e9 {
  strings:
    $key_20e9 = { 74 81 [2] 00 99 [2] 47 9b [2] 00 8a [2] 4e 86 [2] 42 8c [2] 55 87 [2] 4e c9 [2] 73 }

  condition:
    any of them
}