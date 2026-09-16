rule TTP_XOR_MULT_DOSStub_6709 {
  strings:
    $key_6709 = { 33 61 [2] 47 79 [2] 00 7b [2] 47 6a [2] 09 66 [2] 05 6c [2] 12 67 [2] 09 29 [2] 34 }

  condition:
    any of them
}