rule TTP_XOR_MULT_DOSStub_0746 {
  strings:
    $key_0746 = { 53 2e [2] 27 36 [2] 60 34 [2] 27 25 [2] 69 29 [2] 65 23 [2] 72 28 [2] 69 66 [2] 54 }

  condition:
    any of them
}