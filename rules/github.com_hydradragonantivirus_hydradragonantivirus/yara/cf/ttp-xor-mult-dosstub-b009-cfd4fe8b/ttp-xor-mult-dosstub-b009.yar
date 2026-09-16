rule TTP_XOR_MULT_DOSStub_b009 {
  strings:
    $key_b009 = { e4 61 [2] 90 79 [2] d7 7b [2] 90 6a [2] de 66 [2] d2 6c [2] c5 67 [2] de 29 [2] e3 }

  condition:
    any of them
}