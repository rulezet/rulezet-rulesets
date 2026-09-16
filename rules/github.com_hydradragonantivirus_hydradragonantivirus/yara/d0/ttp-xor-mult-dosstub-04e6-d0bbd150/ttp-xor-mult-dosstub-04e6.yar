rule TTP_XOR_MULT_DOSStub_04e6 {
  strings:
    $key_04e6 = { 50 8e [2] 24 96 [2] 63 94 [2] 24 85 [2] 6a 89 [2] 66 83 [2] 71 88 [2] 6a c6 [2] 57 }

  condition:
    any of them
}