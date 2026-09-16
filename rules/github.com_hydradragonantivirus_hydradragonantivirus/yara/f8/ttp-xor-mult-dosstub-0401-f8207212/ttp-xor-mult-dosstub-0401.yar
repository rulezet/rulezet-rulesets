rule TTP_XOR_MULT_DOSStub_0401 {
  strings:
    $key_0401 = { 50 69 [2] 24 71 [2] 63 73 [2] 24 62 [2] 6a 6e [2] 66 64 [2] 71 6f [2] 6a 21 [2] 57 }

  condition:
    any of them
}