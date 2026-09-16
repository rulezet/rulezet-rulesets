rule TTP_XOR_MULT_DOSStub_1608 {
  strings:
    $key_1608 = { 42 60 [2] 36 78 [2] 71 7a [2] 36 6b [2] 78 67 [2] 74 6d [2] 63 66 [2] 78 28 [2] 45 }

  condition:
    any of them
}