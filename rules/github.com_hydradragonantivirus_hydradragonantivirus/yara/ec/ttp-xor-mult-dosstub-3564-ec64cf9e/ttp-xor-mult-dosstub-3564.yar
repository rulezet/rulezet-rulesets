rule TTP_XOR_MULT_DOSStub_3564 {
  strings:
    $key_3564 = { 61 0c [2] 15 14 [2] 52 16 [2] 15 07 [2] 5b 0b [2] 57 01 [2] 40 0a [2] 5b 44 [2] 66 }

  condition:
    any of them
}