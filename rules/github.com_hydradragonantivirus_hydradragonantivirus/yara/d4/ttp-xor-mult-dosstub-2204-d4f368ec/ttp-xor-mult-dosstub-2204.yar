rule TTP_XOR_MULT_DOSStub_2204 {
  strings:
    $key_2204 = { 76 6c [2] 02 74 [2] 45 76 [2] 02 67 [2] 4c 6b [2] 40 61 [2] 57 6a [2] 4c 24 [2] 71 }

  condition:
    any of them
}