rule TTP_XOR_MULT_DOSStub_0744 {
  strings:
    $key_0744 = { 53 2c [2] 27 34 [2] 60 36 [2] 27 27 [2] 69 2b [2] 65 21 [2] 72 2a [2] 69 64 [2] 54 }

  condition:
    any of them
}