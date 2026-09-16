rule TTP_XOR_MULT_DOSStub_5402 {
  strings:
    $key_5402 = { 00 6a [2] 74 72 [2] 33 70 [2] 74 61 [2] 3a 6d [2] 36 67 [2] 21 6c [2] 3a 22 [2] 07 }

  condition:
    any of them
}