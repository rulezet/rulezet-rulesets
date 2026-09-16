rule TTP_XOR_MULT_DOSStub_0447 {
  strings:
    $key_0447 = { 50 2f [2] 24 37 [2] 63 35 [2] 24 24 [2] 6a 28 [2] 66 22 [2] 71 29 [2] 6a 67 [2] 57 }

  condition:
    any of them
}