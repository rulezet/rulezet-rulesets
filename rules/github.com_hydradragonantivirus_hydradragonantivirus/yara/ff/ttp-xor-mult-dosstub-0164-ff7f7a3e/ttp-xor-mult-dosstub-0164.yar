rule TTP_XOR_MULT_DOSStub_0164 {
  strings:
    $key_0164 = { 55 0c [2] 21 14 [2] 66 16 [2] 21 07 [2] 6f 0b [2] 63 01 [2] 74 0a [2] 6f 44 [2] 52 }

  condition:
    any of them
}