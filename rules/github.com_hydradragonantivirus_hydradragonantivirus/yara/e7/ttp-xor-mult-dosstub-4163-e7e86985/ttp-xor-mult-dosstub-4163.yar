rule TTP_XOR_MULT_DOSStub_4163 {
  strings:
    $key_4163 = { 15 0b [2] 61 13 [2] 26 11 [2] 61 00 [2] 2f 0c [2] 23 06 [2] 34 0d [2] 2f 43 [2] 12 }

  condition:
    any of them
}