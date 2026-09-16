rule TTP_XOR_MULT_DOSStub_5d04 {
  strings:
    $key_5d04 = { 09 6c [2] 7d 74 [2] 3a 76 [2] 7d 67 [2] 33 6b [2] 3f 61 [2] 28 6a [2] 33 24 [2] 0e }

  condition:
    any of them
}