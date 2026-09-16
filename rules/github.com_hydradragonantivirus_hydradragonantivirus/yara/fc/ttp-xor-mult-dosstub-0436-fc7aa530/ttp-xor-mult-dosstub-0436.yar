rule TTP_XOR_MULT_DOSStub_0436 {
  strings:
    $key_0436 = { 50 5e [2] 24 46 [2] 63 44 [2] 24 55 [2] 6a 59 [2] 66 53 [2] 71 58 [2] 6a 16 [2] 57 }

  condition:
    any of them
}