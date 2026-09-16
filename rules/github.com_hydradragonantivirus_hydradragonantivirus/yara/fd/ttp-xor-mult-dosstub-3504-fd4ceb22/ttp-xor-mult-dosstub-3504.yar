rule TTP_XOR_MULT_DOSStub_3504 {
  strings:
    $key_3504 = { 61 6c [2] 15 74 [2] 52 76 [2] 15 67 [2] 5b 6b [2] 57 61 [2] 40 6a [2] 5b 24 [2] 66 }

  condition:
    any of them
}