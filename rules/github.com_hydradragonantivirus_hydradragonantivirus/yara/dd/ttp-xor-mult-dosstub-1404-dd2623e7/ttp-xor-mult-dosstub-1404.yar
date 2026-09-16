rule TTP_XOR_MULT_DOSStub_1404 {
  strings:
    $key_1404 = { 40 6c [2] 34 74 [2] 73 76 [2] 34 67 [2] 7a 6b [2] 76 61 [2] 61 6a [2] 7a 24 [2] 47 }

  condition:
    any of them
}