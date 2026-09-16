rule TTP_XOR_MULT_DOSStub_1659 {
  strings:
    $key_1659 = { 42 31 [2] 36 29 [2] 71 2b [2] 36 3a [2] 78 36 [2] 74 3c [2] 63 37 [2] 78 79 [2] 45 }

  condition:
    any of them
}