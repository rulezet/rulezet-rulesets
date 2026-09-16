rule TTP_XOR_MULT_DOSStub_0451 {
  strings:
    $key_0451 = { 50 39 [2] 24 21 [2] 63 23 [2] 24 32 [2] 6a 3e [2] 66 34 [2] 71 3f [2] 6a 71 [2] 57 }

  condition:
    any of them
}