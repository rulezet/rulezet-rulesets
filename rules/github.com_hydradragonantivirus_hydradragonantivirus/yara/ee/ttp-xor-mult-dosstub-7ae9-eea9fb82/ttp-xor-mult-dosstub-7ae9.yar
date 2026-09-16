rule TTP_XOR_MULT_DOSStub_7ae9 {
  strings:
    $key_7ae9 = { 2e 81 [2] 5a 99 [2] 1d 9b [2] 5a 8a [2] 14 86 [2] 18 8c [2] 0f 87 [2] 14 c9 [2] 29 }

  condition:
    any of them
}