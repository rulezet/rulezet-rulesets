rule TTP_XOR_MULT_DOSStub_5604 {
  strings:
    $key_5604 = { 02 6c [2] 76 74 [2] 31 76 [2] 76 67 [2] 38 6b [2] 34 61 [2] 23 6a [2] 38 24 [2] 05 }

  condition:
    any of them
}