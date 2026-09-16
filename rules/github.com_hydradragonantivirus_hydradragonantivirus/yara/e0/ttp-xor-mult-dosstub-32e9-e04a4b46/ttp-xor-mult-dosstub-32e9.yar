rule TTP_XOR_MULT_DOSStub_32e9 {
  strings:
    $key_32e9 = { 66 81 [2] 12 99 [2] 55 9b [2] 12 8a [2] 5c 86 [2] 50 8c [2] 47 87 [2] 5c c9 [2] 61 }

  condition:
    any of them
}