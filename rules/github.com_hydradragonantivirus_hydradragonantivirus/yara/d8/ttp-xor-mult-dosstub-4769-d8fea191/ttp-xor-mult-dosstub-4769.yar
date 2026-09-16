rule TTP_XOR_MULT_DOSStub_4769 {
  strings:
    $key_4769 = { 13 01 [2] 67 19 [2] 20 1b [2] 67 0a [2] 29 06 [2] 25 0c [2] 32 07 [2] 29 49 [2] 14 }

  condition:
    any of them
}