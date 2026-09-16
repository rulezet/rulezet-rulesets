rule TTP_XOR_MULT_DOSStub_4164 {
  strings:
    $key_4164 = { 15 0c [2] 61 14 [2] 26 16 [2] 61 07 [2] 2f 0b [2] 23 01 [2] 34 0a [2] 2f 44 [2] 12 }

  condition:
    any of them
}