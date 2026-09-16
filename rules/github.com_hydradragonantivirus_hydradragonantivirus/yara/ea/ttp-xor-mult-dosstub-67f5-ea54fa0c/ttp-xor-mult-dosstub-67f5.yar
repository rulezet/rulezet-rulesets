rule TTP_XOR_MULT_DOSStub_67f5 {
  strings:
    $key_67f5 = { 33 9d [2] 47 85 [2] 00 87 [2] 47 96 [2] 09 9a [2] 05 90 [2] 12 9b [2] 09 d5 [2] 34 }

  condition:
    any of them
}