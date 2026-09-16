rule TTP_XOR_MULT_DOSStub_46e6 {
  strings:
    $key_46e6 = { 12 8e [2] 66 96 [2] 21 94 [2] 66 85 [2] 28 89 [2] 24 83 [2] 33 88 [2] 28 c6 [2] 15 }

  condition:
    any of them
}