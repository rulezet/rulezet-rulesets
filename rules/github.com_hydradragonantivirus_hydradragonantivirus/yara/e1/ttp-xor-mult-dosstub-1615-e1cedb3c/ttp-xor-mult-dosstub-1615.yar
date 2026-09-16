rule TTP_XOR_MULT_DOSStub_1615 {
  strings:
    $key_1615 = { 42 7d [2] 36 65 [2] 71 67 [2] 36 76 [2] 78 7a [2] 74 70 [2] 63 7b [2] 78 35 [2] 45 }

  condition:
    any of them
}