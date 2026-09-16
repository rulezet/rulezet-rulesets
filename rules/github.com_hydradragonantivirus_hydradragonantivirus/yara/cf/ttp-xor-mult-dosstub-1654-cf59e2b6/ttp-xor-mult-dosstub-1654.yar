rule TTP_XOR_MULT_DOSStub_1654 {
  strings:
    $key_1654 = { 42 3c [2] 36 24 [2] 71 26 [2] 36 37 [2] 78 3b [2] 74 31 [2] 63 3a [2] 78 74 [2] 45 }

  condition:
    any of them
}