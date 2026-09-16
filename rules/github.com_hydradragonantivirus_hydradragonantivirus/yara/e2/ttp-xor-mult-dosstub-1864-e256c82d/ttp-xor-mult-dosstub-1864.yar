rule TTP_XOR_MULT_DOSStub_1864 {
  strings:
    $key_1864 = { 4c 0c [2] 38 14 [2] 7f 16 [2] 38 07 [2] 76 0b [2] 7a 01 [2] 6d 0a [2] 76 44 [2] 4b }

  condition:
    any of them
}