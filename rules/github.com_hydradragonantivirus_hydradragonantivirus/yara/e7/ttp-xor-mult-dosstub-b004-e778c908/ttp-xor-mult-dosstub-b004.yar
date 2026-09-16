rule TTP_XOR_MULT_DOSStub_b004 {
  strings:
    $key_b004 = { e4 6c [2] 90 74 [2] d7 76 [2] 90 67 [2] de 6b [2] d2 61 [2] c5 6a [2] de 24 [2] e3 }

  condition:
    any of them
}