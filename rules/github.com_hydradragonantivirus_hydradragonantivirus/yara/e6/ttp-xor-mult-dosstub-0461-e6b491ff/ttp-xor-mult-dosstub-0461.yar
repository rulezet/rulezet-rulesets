rule TTP_XOR_MULT_DOSStub_0461 {
  strings:
    $key_0461 = { 50 09 [2] 24 11 [2] 63 13 [2] 24 02 [2] 6a 0e [2] 66 04 [2] 71 0f [2] 6a 41 [2] 57 }

  condition:
    any of them
}