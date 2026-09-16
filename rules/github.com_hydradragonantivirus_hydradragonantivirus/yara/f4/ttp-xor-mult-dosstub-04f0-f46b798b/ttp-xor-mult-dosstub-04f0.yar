rule TTP_XOR_MULT_DOSStub_04f0 {
  strings:
    $key_04f0 = { 50 98 [2] 24 80 [2] 63 82 [2] 24 93 [2] 6a 9f [2] 66 95 [2] 71 9e [2] 6a d0 [2] 57 }

  condition:
    any of them
}