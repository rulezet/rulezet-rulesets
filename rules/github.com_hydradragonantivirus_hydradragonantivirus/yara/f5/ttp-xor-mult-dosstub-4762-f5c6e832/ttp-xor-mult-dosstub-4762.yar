rule TTP_XOR_MULT_DOSStub_4762 {
  strings:
    $key_4762 = { 13 0a [2] 67 12 [2] 20 10 [2] 67 01 [2] 29 0d [2] 25 07 [2] 32 0c [2] 29 42 [2] 14 }

  condition:
    any of them
}