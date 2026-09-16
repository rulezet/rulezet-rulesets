rule TTP_XOR_MULT_DOSStub_01e9 {
  strings:
    $key_01e9 = { 55 81 [2] 21 99 [2] 66 9b [2] 21 8a [2] 6f 86 [2] 63 8c [2] 74 87 [2] 6f c9 [2] 52 }

  condition:
    any of them
}