rule TTP_XOR_MULT_DOSStub_1638 {
  strings:
    $key_1638 = { 42 50 [2] 36 48 [2] 71 4a [2] 36 5b [2] 78 57 [2] 74 5d [2] 63 56 [2] 78 18 [2] 45 }

  condition:
    any of them
}