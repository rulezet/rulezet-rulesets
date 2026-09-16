rule TTP_XOR_MULT_DOSStub_0751 {
  strings:
    $key_0751 = { 53 39 [2] 27 21 [2] 60 23 [2] 27 32 [2] 69 3e [2] 65 34 [2] 72 3f [2] 69 71 [2] 54 }

  condition:
    any of them
}