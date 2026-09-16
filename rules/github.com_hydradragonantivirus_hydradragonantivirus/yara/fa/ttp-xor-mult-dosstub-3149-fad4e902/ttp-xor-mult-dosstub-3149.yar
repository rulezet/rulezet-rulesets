rule TTP_XOR_MULT_DOSStub_3149 {
  strings:
    $key_3149 = { 65 21 [2] 11 39 [2] 56 3b [2] 11 2a [2] 5f 26 [2] 53 2c [2] 44 27 [2] 5f 69 [2] 62 }

  condition:
    any of them
}