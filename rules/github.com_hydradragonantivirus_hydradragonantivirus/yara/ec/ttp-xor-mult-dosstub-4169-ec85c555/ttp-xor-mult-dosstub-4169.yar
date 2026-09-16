rule TTP_XOR_MULT_DOSStub_4169 {
  strings:
    $key_4169 = { 15 01 [2] 61 19 [2] 26 1b [2] 61 0a [2] 2f 06 [2] 23 0c [2] 34 07 [2] 2f 49 [2] 12 }

  condition:
    any of them
}