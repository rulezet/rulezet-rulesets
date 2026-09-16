rule TTP_XOR_MULT_DOSStub_42e9 {
  strings:
    $key_42e9 = { 16 81 [2] 62 99 [2] 25 9b [2] 62 8a [2] 2c 86 [2] 20 8c [2] 37 87 [2] 2c c9 [2] 11 }

  condition:
    any of them
}